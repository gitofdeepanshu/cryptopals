use std::{
    future::{self, Future},
    pin::Pin,
    ptr,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use async_std::fs::read_to_string;

struct BlockingExecutor;

impl BlockingExecutor {
    pub fn run<F>(f: F) -> F::Output
    where
        F: Future,
        F::Output: Debug,
    {
    }
}
struct ConstantFuture {
    value: i32,
}

impl ConstantFuture {
    pub fn new(val: i32) -> Self {
        ConstantFuture { value: val }
    }
}

impl Future for ConstantFuture {
    type Output = i32;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Poll::Ready(self.value)
    }
}

struct Executor;

impl Executor {
    pub fn run<F: Future>(f: F) -> F::Output {
        let mut boxed_future: Pin<Box<F>> = Box::pin(f);
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);

        let result = boxed_future.as_mut().poll(&mut context);

        if let Poll::Ready(a) = result {
            return a;
        } else {
            panic!("This executor doesn't really do anything! You asked it to do too much!");
        }
    }
}

fn noop_waker() -> Waker {
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

fn noop_raw_waker() -> RawWaker {
    RawWaker::new(ptr::null(), &RAW_WAKER_VTABLE)
}

unsafe fn noop(_p: *const ()) {}
unsafe fn noop_clone(_p: *const ()) -> RawWaker {
    noop_raw_waker()
}

const RAW_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);

fn main() {
    let result = Executor::run(read_file());
    println!("result = {}", result);
}

async fn identity(value: i32) -> i32 {
    value
}

async fn read_file() -> String {
    let contents = read_to_string("test.txt").await;
    contents.expect("Error openning file")
}
