#[repr(C)]
pub struct GArray<T=i8> {
    data: *mut T,
    len: u32,
}

impl<T> GArray<T> {
    pub fn as_slice(&self) -> Option<&[T]> {
        if self.data.is_null() {
            return None;
        }

        Some(unsafe {
            std::slice::from_raw_parts(self.data, self.len as usize)
        })
    }
}

pub type GByteArray = GArray<u8>;

#[repr(transparent)]
pub struct Owned<T: SpecializedDrop>(T);

impl<T> Owned<*mut GArray<T>> {
    pub fn as_slice(&self) -> Option<&[T]> {
        unsafe {
            self.0.as_ref().and_then(GArray::<T>::as_slice)
        }
    }
}


impl<T: SpecializedDrop> std::ops::Deref for Owned<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait SpecializedDrop: Sized {
    fn drop(owned: &mut Owned<Self>);
}

impl<T> SpecializedDrop for *mut GArray<T> {
    fn drop(owned: &mut Owned<Self>) {
        if !owned.0.is_null() {
            unsafe {
                g_array_free(owned.0 as _, true);
            }
        }
    }
}

impl<T: SpecializedDrop> Drop for Owned<T> {
    fn drop(&mut self) {
        <T as SpecializedDrop>::drop(self)
    }
}

extern "C" {
    pub fn g_byte_array_new() -> Owned<*mut GByteArray>;
    pub fn g_array_free(_array: *mut GArray, free_segment: bool) -> *mut i8;
    pub fn g_byte_array_set_size(_array: *mut GByteArray, _length: u32) -> *mut GByteArray;
}
