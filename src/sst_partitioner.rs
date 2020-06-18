// Copyright 2020 TiKV Project Authors. Licensed under Apache-2.0.

use crocksdb_ffi::{
    self, DBSstPartitioner, DBSstPartitionerContext, DBSstPartitionerFactory, DBSstPartitionerState,
};
use libc::{c_char, c_uchar, c_void, size_t};
use std::{ffi::CString, mem, slice};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SstPartitionerState<'a> {
    pub next_key: &'a [u8],
    pub current_output_file_size: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SstPartitionerContext<'a> {
    pub is_full_compaction: bool,
    pub is_manual_compaction: bool,
    pub output_level: i32,
    pub smallest_key: &'a [u8],
    pub largest_key: &'a [u8],
}

pub trait SstPartitioner {
    fn should_partition(&self, state: &SstPartitionerState) -> bool;
    fn reset(&self, key: &[u8]);
}

extern "C" fn sst_partitioner_destructor(ctx: *mut c_void) {
    unsafe {
        // Recover from raw pointer and implicitly drop.
        Box::from_raw(ctx as *mut Box<dyn SstPartitioner>);
    }
}

extern "C" fn sst_partitioner_should_partition(
    ctx: *mut c_void,
    state: *mut DBSstPartitionerState,
) -> c_uchar {
    let partitioner = unsafe { &*(ctx as *mut Box<dyn SstPartitioner>) };
    let state = unsafe {
        let mut key_len: usize = 0;
        let next_key: *const u8 = mem::transmute(
            crocksdb_ffi::crocksdb_sst_partitioner_state_next_key(state, &mut key_len),
        );
        SstPartitionerState {
            next_key: slice::from_raw_parts(next_key, key_len),
            current_output_file_size:
                crocksdb_ffi::crocksdb_sst_partitioner_state_current_output_file_size(state),
        }
    };
    partitioner.should_partition(&state) as _
}

extern "C" fn sst_partitioner_reset(ctx: *mut c_void, key: *const c_char, key_len: size_t) {
    let partitioner = unsafe { &*(ctx as *mut Box<dyn SstPartitioner>) };
    let key_buf = unsafe {
        let key_ptr: *const u8 = mem::transmute(key);
        slice::from_raw_parts(key_ptr, key_len)
    };
    partitioner.reset(key_buf);
}

pub trait SstPartitionerFactory: Sync + Send {
    fn name(&self) -> &CString;
    fn create_partitioner(&self, context: &SstPartitionerContext) -> Box<dyn SstPartitioner>;
}

extern "C" fn sst_partitioner_factory_destroy(ctx: *mut c_void) {
    unsafe {
        // Recover from raw pointer and implicitly drop.
        Box::from_raw(ctx as *mut Box<dyn SstPartitionerFactory>);
    }
}

extern "C" fn sst_partitioner_factory_name(ctx: *mut c_void) -> *const c_char {
    let factory = unsafe { &*(ctx as *mut Box<dyn SstPartitionerFactory>) };
    factory.name().as_ptr()
}

extern "C" fn sst_partitioner_factory_create_partitioner(
    ctx: *mut c_void,
    context: *mut DBSstPartitionerContext,
) -> *mut DBSstPartitioner {
    let factory = unsafe { &*(ctx as *mut Box<dyn SstPartitionerFactory>) };
    let context = unsafe {
        let mut smallest_key_len: usize = 0;
        let smallest_key: *const u8 =
            mem::transmute(crocksdb_ffi::crocksdb_sst_partitioner_context_smallest_key(
                context,
                &mut smallest_key_len,
            ));
        let mut largest_key_len: usize = 0;
        let largest_key: *const u8 =
            mem::transmute(crocksdb_ffi::crocksdb_sst_partitioner_context_largest_key(
                context,
                &mut largest_key_len,
            ));
        SstPartitionerContext {
            is_full_compaction: crocksdb_ffi::crocksdb_sst_partitioner_context_is_full_compaction(
                context,
            ) != 0,
            is_manual_compaction:
                crocksdb_ffi::crocksdb_sst_partitioner_context_is_manual_compaction(context) != 0,
            output_level: crocksdb_ffi::crocksdb_sst_partitioner_context_output_level(context),
            smallest_key: slice::from_raw_parts(smallest_key, smallest_key_len),
            largest_key: slice::from_raw_parts(largest_key, largest_key_len),
        }
    };
    let partitioner = factory.create_partitioner(&context);
    let ctx = Box::into_raw(Box::new(partitioner)) as *mut c_void;
    unsafe {
        crocksdb_ffi::crocksdb_sst_partitioner_create(
            ctx,
            sst_partitioner_destructor,
            sst_partitioner_should_partition,
            sst_partitioner_reset,
        )
    }
}

pub fn new_sst_partitioner_factory<F: SstPartitionerFactory>(
    factory: F,
) -> *mut DBSstPartitionerFactory {
    let factory: Box<dyn SstPartitionerFactory> = Box::new(factory);
    unsafe {
        crocksdb_ffi::crocksdb_sst_partitioner_factory_create(
            Box::into_raw(Box::new(factory)) as *mut c_void,
            sst_partitioner_factory_destroy,
            sst_partitioner_factory_name,
            sst_partitioner_factory_create_partitioner,
        )
    }
}

#[cfg(test)]
mod test {
    use std::{
        ffi::{CStr, CString},
        mem,
        sync::{Arc, Mutex},
    };

    use super::*;

    struct TestState {
        pub call_create_partitioner: usize,
        pub call_should_partition: usize,
        pub call_reset: usize,
        pub drop_partitioner: usize,
        pub drop_factory: usize,
        pub should_partition_result: bool,

        // SstPartitionerState fields
        pub next_key: Option<Vec<u8>>,
        pub current_output_file_size: Option<u64>,

        pub reset_key: Option<Vec<u8>>,

        // SstPartitionerContext fields
        pub is_full_compaction: Option<bool>,
        pub is_manual_compaction: Option<bool>,
        pub output_level: Option<i32>,
        pub smallest_key: Option<Vec<u8>>,
        pub largest_key: Option<Vec<u8>>,
    }

    impl Default for TestState {
        fn default() -> Self {
            TestState {
                call_create_partitioner: 0,
                call_should_partition: 0,
                call_reset: 0,
                drop_partitioner: 0,
                drop_factory: 0,
                should_partition_result: false,
                next_key: None,
                current_output_file_size: None,
                reset_key: None,
                is_full_compaction: None,
                is_manual_compaction: None,
                output_level: None,
                smallest_key: None,
                largest_key: None,
            }
        }
    }

    struct TestSstPartitioner {
        state: Arc<Mutex<TestState>>,
    }

    impl SstPartitioner for TestSstPartitioner {
        fn should_partition(&self, state: &SstPartitionerState) -> bool {
            let mut s = self.state.lock().unwrap();
            s.call_should_partition += 1;
            s.next_key = Some(state.next_key.to_vec());
            s.current_output_file_size = Some(state.current_output_file_size);

            s.should_partition_result
        }

        fn reset(&self, key: &[u8]) {
            let mut s = self.state.lock().unwrap();
            s.call_reset += 1;
            s.reset_key = Some(key.to_vec());
        }
    }

    impl Drop for TestSstPartitioner {
        fn drop(&mut self) {
            self.state.lock().unwrap().drop_partitioner += 1;
        }
    }

    lazy_static! {
        static ref FACTORY_NAME: CString =
            CString::new(b"TestSstPartitionerFactory".to_vec()).unwrap();
    }

    struct TestSstPartitionerFactory {
        state: Arc<Mutex<TestState>>,
    }

    impl SstPartitionerFactory for TestSstPartitionerFactory {
        fn name(&self) -> &CString {
            &FACTORY_NAME
        }

        fn create_partitioner(&self, context: &SstPartitionerContext) -> Box<dyn SstPartitioner> {
            let mut s = self.state.lock().unwrap();
            s.call_create_partitioner += 1;
            s.is_full_compaction = Some(context.is_full_compaction);
            s.is_manual_compaction = Some(context.is_manual_compaction);
            s.output_level = Some(context.output_level);
            s.smallest_key = Some(context.smallest_key.to_vec());
            s.largest_key = Some(context.largest_key.to_vec());

            Box::new(TestSstPartitioner {
                state: self.state.clone(),
            })
        }
    }

    impl Drop for TestSstPartitionerFactory {
        fn drop(&mut self) {
            self.state.lock().unwrap().drop_factory += 1;
        }
    }

    #[test]
    fn factory_name() {
        let s = Arc::new(Mutex::new(TestState::default()));
        let factory = new_sst_partitioner_factory(TestSstPartitionerFactory { state: s });
        let factory_name =
            unsafe { CStr::from_ptr(crocksdb_ffi::crocksdb_sst_partitioner_factory_name(factory)) };
        assert_eq!(*FACTORY_NAME.as_c_str(), *factory_name);
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_factory_destroy(factory);
        }
    }

    #[test]
    fn factory_create_partitioner() {
        const IS_FULL_COMPACTION: bool = false;
        const IS_MANUAL_COMPACTION: bool = true;
        const OUTPUT_LEVEL: i32 = 3;
        const SMALLEST_KEY: &[u8] = b"aaaa";
        const LARGEST_KEY: &[u8] = b"bbbb";

        let s = Arc::new(Mutex::new(TestState::default()));
        let factory = new_sst_partitioner_factory(TestSstPartitionerFactory { state: s.clone() });
        let context = unsafe { crocksdb_ffi::crocksdb_sst_partitioner_context_create() };
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_context_set_is_full_compaction(
                context,
                IS_FULL_COMPACTION as _,
            );
            crocksdb_ffi::crocksdb_sst_partitioner_context_set_is_manual_compaction(
                context,
                IS_MANUAL_COMPACTION as _,
            );
            crocksdb_ffi::crocksdb_sst_partitioner_context_set_output_level(context, OUTPUT_LEVEL);
            crocksdb_ffi::crocksdb_sst_partitioner_context_set_smallest_key(
                context,
                mem::transmute(SMALLEST_KEY.as_ptr()),
                SMALLEST_KEY.len(),
            );
            crocksdb_ffi::crocksdb_sst_partitioner_context_set_largest_key(
                context,
                mem::transmute(LARGEST_KEY.as_ptr()),
                LARGEST_KEY.len(),
            );
        }
        let partitioner = unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_factory_create_partitioner(factory, context)
        };
        {
            let sl = s.lock().unwrap();
            assert_eq!(1, sl.call_create_partitioner);
            assert_eq!(IS_FULL_COMPACTION, sl.is_full_compaction.unwrap());
            assert_eq!(IS_MANUAL_COMPACTION, sl.is_manual_compaction.unwrap());
            assert_eq!(OUTPUT_LEVEL, sl.output_level.unwrap());
            assert_eq!(SMALLEST_KEY, sl.smallest_key.as_ref().unwrap().as_slice());
            assert_eq!(LARGEST_KEY, sl.largest_key.as_ref().unwrap().as_slice());
        }
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_destroy(partitioner);
            crocksdb_ffi::crocksdb_sst_partitioner_factory_destroy(factory);
        }
    }

    #[test]
    fn partitioner_should_partition() {
        const SHOULD_PARTITION: bool = true;
        const NEXT_KEY: &[u8] = b"test_next_key";
        const CURRENT_OUTPUT_FILE_SIZE: u64 = 1234567;

        let s = Arc::new(Mutex::new(TestState::default()));
        s.lock().unwrap().should_partition_result = SHOULD_PARTITION;
        let factory = new_sst_partitioner_factory(TestSstPartitionerFactory { state: s.clone() });
        let context = unsafe { crocksdb_ffi::crocksdb_sst_partitioner_context_create() };
        let partitioner = unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_factory_create_partitioner(factory, context)
        };
        let state = unsafe { crocksdb_ffi::crocksdb_sst_partitioner_state_create() };
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_state_set_next_key(
                state,
                mem::transmute(NEXT_KEY.as_ptr()),
                NEXT_KEY.len(),
            );
            crocksdb_ffi::crocksdb_sst_partitioner_state_set_current_output_file_size(
                state,
                CURRENT_OUTPUT_FILE_SIZE,
            );
        }
        let should_partition = unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_should_partition(partitioner, state) != 0
        };
        assert_eq!(SHOULD_PARTITION, should_partition);
        {
            let sl = s.lock().unwrap();
            assert_eq!(1, sl.call_create_partitioner);
            assert_eq!(1, sl.call_should_partition);
            assert_eq!(0, sl.call_reset);
            assert_eq!(NEXT_KEY, sl.next_key.as_ref().unwrap().as_slice());
            assert_eq!(
                CURRENT_OUTPUT_FILE_SIZE,
                sl.current_output_file_size.unwrap()
            );
        }
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_destroy(partitioner);
            crocksdb_ffi::crocksdb_sst_partitioner_factory_destroy(factory);
        }
    }

    #[test]
    fn partitioner_reset() {
        const RESET_KEY: &[u8] = b"test_reset_key";

        let s = Arc::new(Mutex::new(TestState::default()));
        let factory = new_sst_partitioner_factory(TestSstPartitionerFactory { state: s.clone() });
        let context = unsafe { crocksdb_ffi::crocksdb_sst_partitioner_context_create() };
        let partitioner = unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_factory_create_partitioner(factory, context)
        };
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_reset(
                partitioner,
                mem::transmute(RESET_KEY.as_ptr()),
                RESET_KEY.len(),
            );
        }
        {
            let sl = s.lock().unwrap();
            assert_eq!(1, sl.call_create_partitioner);
            assert_eq!(0, sl.call_should_partition);
            assert_eq!(1, sl.call_reset);
            assert_eq!(RESET_KEY, sl.reset_key.as_ref().unwrap().as_slice());
        }
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_destroy(partitioner);
            crocksdb_ffi::crocksdb_sst_partitioner_factory_destroy(factory);
        }
    }

    #[test]
    fn drop() {
        let s = Arc::new(Mutex::new(TestState::default()));
        let factory = new_sst_partitioner_factory(TestSstPartitionerFactory { state: s.clone() });
        let context = unsafe { crocksdb_ffi::crocksdb_sst_partitioner_context_create() };
        let partitioner = unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_factory_create_partitioner(factory, context)
        };
        {
            let sl = s.lock().unwrap();
            assert_eq!(0, sl.drop_partitioner);
            assert_eq!(0, sl.drop_factory);
        }
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_destroy(partitioner);
        }
        {
            let sl = s.lock().unwrap();
            assert_eq!(1, sl.drop_partitioner);
            assert_eq!(0, sl.drop_factory);
        }
        unsafe {
            crocksdb_ffi::crocksdb_sst_partitioner_factory_destroy(factory);
        }
        {
            let sl = s.lock().unwrap();
            assert_eq!(1, sl.drop_partitioner);
            assert_eq!(1, sl.drop_factory);
        }
    }
}
