use alloc::vec::Vec;
use alloc::boxed::Box;

#[derive(Clone, Debug)]
pub struct Vector<T> {
    pub data: Vec<T>,
}

impl<T: Clone> Vector<T> {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }

    pub fn push(&mut self, value: T) {
        self.data.push(value);
    }

    pub fn get(&self, index: usize) -> T {
        self.data[index].clone()
    }

    pub fn set(&mut self, index: usize, value: T) {
        self.data[index] = value;
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn iter(&self) -> core::slice::Iter<T> {
        self.data.iter()
    }

    pub fn iter_mut(&mut self) -> core::slice::IterMut<T> {
        self.data.iter_mut()
    }

    pub fn into_boxed_slice(self) -> Box<[T]> {
        self.data.into_boxed_slice()
    }
}