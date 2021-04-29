// Copyright 2020 TiKV Project Authors. Licensed under Apache-2.0.

pub use crocksdb_ffi::{self, DBFileSystemInspectorInstance};

use libc::{c_char, c_void, size_t, strdup};

// Inspect global IO flow. No per-file inspection for now.
pub trait FileSystemInspector: Sync + Send {
    fn read_begin(&self, len: usize) -> Result<usize, String>;
    fn read_end(&self, len: usize);
    fn write_begin(&self, len: usize) -> Result<usize, String>;
    fn write_end(&self, len: usize);
}

extern "C" fn file_system_inspector_destructor<T: FileSystemInspector>(ctx: *mut c_void) {
    unsafe {
        // Recover from raw pointer and implicitly drop.
        Box::from_raw(ctx as *mut T);
    }
}

extern "C" fn file_system_inspector_read_begin<T: FileSystemInspector>(
    ctx: *mut c_void,
    len: size_t,
    errptr: *mut *mut c_char,
) -> size_t {
    let file_system_inspector = unsafe { &*(ctx as *mut T) };
    match file_system_inspector.read_begin(len) {
        Ok(ret) => ret,
        Err(e) => {
            unsafe {
                *errptr = strdup(e.as_ptr() as *const c_char);
            }
            0
        }
    }
}

extern "C" fn file_system_inspector_read_end<T: FileSystemInspector>(
    ctx: *mut c_void,
    len: size_t,
) {
    let file_system_inspector = unsafe { &*(ctx as *mut T) };
    file_system_inspector.read_end(len);
}

extern "C" fn file_system_inspector_write_begin<T: FileSystemInspector>(
    ctx: *mut c_void,
    len: size_t,
    errptr: *mut *mut c_char,
) -> size_t {
    let file_system_inspector = unsafe { &*(ctx as *mut T) };
    match file_system_inspector.write_begin(len) {
        Ok(ret) => ret,
        Err(e) => {
            unsafe {
                *errptr = strdup(e.as_ptr() as *const c_char);
            }
            0
        }
    }
}

extern "C" fn file_system_inspector_write_end<T: FileSystemInspector>(
    ctx: *mut c_void,
    len: size_t,
) {
    let file_system_inspector = unsafe { &*(ctx as *mut T) };
    file_system_inspector.write_end(len);
}

pub struct DBFileSystemInspector {
    pub inner: *mut DBFileSystemInspectorInstance,
}

unsafe impl Send for DBFileSystemInspector {}
unsafe impl Sync for DBFileSystemInspector {}

impl DBFileSystemInspector {
    pub fn new<T: FileSystemInspector>(file_system_inspector: T) -> DBFileSystemInspector {
        let ctx = Box::into_raw(Box::new(file_system_inspector)) as *mut c_void;
        let instance = unsafe {
            crocksdb_ffi::crocksdb_file_system_inspector_create(
                ctx,
                file_system_inspector_destructor::<T>,
                file_system_inspector_read_begin::<T>,
                file_system_inspector_read_end::<T>,
                file_system_inspector_write_begin::<T>,
                file_system_inspector_write_end::<T>,
            )
        };
        DBFileSystemInspector { inner: instance }
    }
}

impl Drop for DBFileSystemInspector {
    fn drop(&mut self) {
        unsafe {
            crocksdb_ffi::crocksdb_file_system_inspector_destroy(self.inner);
        }
    }
}

#[cfg(test)]
impl FileSystemInspector for DBFileSystemInspector {
    fn read_begin(&self, len: usize) -> Result<usize, String> {
        let ret = unsafe { ffi_try!(crocksdb_file_system_inspector_read_begin(self.inner, len)) };
        Ok(ret)
    }
    fn read_end(&self, len: usize) {
        unsafe { ffi_try!(crocksdb_file_system_inspector_read(self.inner, len)) };
    }
    fn write_begin(&self, len: usize) -> Result<usize, String> {
        let ret = unsafe { ffi_try!(crocksdb_file_system_inspector_write(self.inner, len)) };
        Ok(ret)
    }
    fn write_end(&self, len: usize) {
        unsafe { ffi_try!(crocksdb_file_system_inspector_read(self.inner, len)) };
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    struct TestDrop {
        called: Arc<AtomicUsize>,
    }

    impl Drop for TestDrop {
        fn drop(&mut self) {
            self.called.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TestFileSystemInspector {
        pub refill_bytes: usize,
        pub read_called: usize,
        pub read_finished: usize,
        pub write_called: usize,
        pub write_finished: usize,
        pub drop: Option<TestDrop>,
    }

    impl Default for TestFileSystemInspector {
        fn default() -> Self {
            TestFileSystemInspector {
                refill_bytes: 0,
                read_called: 0,
                read_finished: 0,
                write_called: 0,
                write_finished: 0,
                drop: None,
            }
        }
    }

    impl FileSystemInspector for Arc<Mutex<TestFileSystemInspector>> {
        fn read_begin(&self, len: usize) -> Result<usize, String> {
            let mut inner = self.lock().unwrap();
            inner.read_called += 1;
            if len <= inner.refill_bytes {
                Ok(len)
            } else {
                Err("request exceeds refill bytes".into())
            }
        }
        fn read_end(&self, len: usize) {
            let mut inner = self.lock().unwrap();
            inner.read_finished += 1;
        }
        fn write_begin(&self, len: usize) -> Result<usize, String> {
            let mut inner = self.lock().unwrap();
            inner.write_called += 1;
            if len <= inner.refill_bytes {
                Ok(len)
            } else {
                Err("request exceeds refill bytes".into())
            }
        }
        fn write_end(&self, len: usize) {
            let mut inner = self.lock().unwrap();
            inner.write_finished += 1;
        }
    }

    #[test]
    fn test_create_and_destroy_inspector() {
        let drop_called = Arc::new(AtomicUsize::new(0));
        let fs_inspector = Arc::new(Mutex::new(TestFileSystemInspector {
            drop: Some(TestDrop {
                called: drop_called.clone(),
            }),
            ..Default::default()
        }));
        let db_fs_inspector = DBFileSystemInspector::new(fs_inspector.clone());
        drop(fs_inspector);
        assert_eq!(0, drop_called.load(Ordering::SeqCst));
        drop(db_fs_inspector);
        assert_eq!(1, drop_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_inspected_operation() {
        let fs_inspector = Arc::new(Mutex::new(TestFileSystemInspector {
            refill_bytes: 4,
            ..Default::default()
        }));
        let db_fs_inspector = DBFileSystemInspector::new(fs_inspector.clone());
        assert_eq!(2, db_fs_inspector.read(2).unwrap());
        assert!(db_fs_inspector.read(8).is_err());
        assert_eq!(2, db_fs_inspector.write(2).unwrap());
        assert!(db_fs_inspector.write(8).is_err());
        let record = fs_inspector.lock().unwrap();
        assert_eq!(2, record.read_called);
        assert_eq!(2, record.read_finished);
        assert_eq!(2, record.write_called);
        assert_eq!(2, record.write_finished);
    }
}
