//! Implementation of syscalls
//!
//! The single entry point to all system calls, [`syscall()`], is called
//! whenever userspace wishes to perform a system call using the `ecall`
//! instruction. In this case, the processor raises an 'Environment call from
//! U-mode' exception, which is handled as one of the cases in
//! [`crate::trap::trap_handler`].
//!
//! For clarity, each single syscall is implemented as its own function, named
//! `sys_` then the name of the syscall. You can find functions like this in
//! submodules, and you should also implement syscalls this way.

const SYSCALL_UNLINKAT: usize = 35;
const SYSCALL_LINKAT: usize = 37;
const SYSCALL_OPEN: usize = 56;
const SYSCALL_CLOSE: usize = 57;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_FSTAT: usize = 80;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_GET_TIME: usize = 169;
const SYSCALL_GETPID: usize = 172;
const SYSCALL_FORK: usize = 220;
const SYSCALL_EXEC: usize = 221;
const SYSCALL_WAITPID: usize = 260;
const SYSCALL_SPAWN: usize = 400;
const SYSCALL_MUNMAP: usize = 215;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_SET_PRIORITY: usize = 140;
const SYSCALL_TASK_INFO: usize = 410;

mod fs;
pub mod process;

use fs::*;
use process::*;
use crate::fs::Stat;
use crate::task::current_task;

/// handle syscall exception with `syscall_id` and other arguments
pub fn syscall(syscall_id: usize, args: [usize; 4]) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    match syscall_id {
        SYSCALL_LINKAT => {
            inner.syscall_times[SYSCALL_LINKAT]+=1;
            drop(inner);
            return sys_linkat(args[1] as *const u8, args[3] as *const u8);
        },
        SYSCALL_UNLINKAT => {
            inner.syscall_times[SYSCALL_UNLINKAT]+=1;
            drop(inner);
            return sys_unlinkat(args[1] as *const u8);
        },
        SYSCALL_OPEN => {
            inner.syscall_times[SYSCALL_OPEN]+=1;
            drop(inner);
            return sys_open(args[1] as *const u8, args[2] as u32);
        },
        SYSCALL_CLOSE => {
            inner.syscall_times[SYSCALL_CLOSE]+=1;
            drop(inner);
            return sys_close(args[0]);},
        SYSCALL_READ => {
            inner.syscall_times[SYSCALL_READ]+=1;
            drop(inner);
            return sys_read(args[0], args[1] as *const u8, args[2]);
        }
        SYSCALL_WRITE => {
            inner.syscall_times[SYSCALL_WRITE]+=1;
            drop(inner);
            return sys_write(args[0], args[1] as *const u8, args[2]);
        }
        SYSCALL_FSTAT => {
            inner.syscall_times[SYSCALL_FSTAT]+=1;
            drop(inner);
            return sys_fstat(args[0], args[1] as *mut Stat);
        },
        SYSCALL_EXIT => {
            inner.syscall_times[SYSCALL_EXIT]+=1;
            drop(inner);
            sys_exit(args[0] as i32);
        }
        SYSCALL_YIELD => {
            inner.syscall_times[SYSCALL_YIELD]+=1;
            drop(inner);
            return sys_yield();
        },
        SYSCALL_GETPID => {
            inner.syscall_times[SYSCALL_GETPID]+=1;
            drop(inner);
            return sys_getpid();
        },
        SYSCALL_FORK => {
            inner.syscall_times[SYSCALL_FORK]+=1;
            drop(inner);
            return sys_fork();
        },
        SYSCALL_EXEC => {
            inner.syscall_times[SYSCALL_EXEC]+=1;
            drop(inner);
            return sys_exec(args[0] as *const u8);
        },
        SYSCALL_WAITPID => {
            inner.syscall_times[SYSCALL_WAITPID]+=1;
            drop(inner);
            return sys_waitpid(args[0] as isize, args[1] as *mut i32);
        },
        SYSCALL_GET_TIME => {
            inner.syscall_times[SYSCALL_GET_TIME]+=1;
            drop(inner);
            return sys_get_time(args[0] as *mut TimeVal, args[1]);
        },
        SYSCALL_MMAP => {
            inner.syscall_times[SYSCALL_MMAP]+=1;
            drop(inner);
            return sys_mmap(args[0], args[1], args[2]);
        },
        SYSCALL_MUNMAP => {
            inner.syscall_times[SYSCALL_MUNMAP]+=1;
            drop(inner);
            return sys_munmap(args[0], args[1]);
        },
        SYSCALL_SET_PRIORITY => {
            inner.syscall_times[SYSCALL_SET_PRIORITY]+=1;
            drop(inner);
            return sys_set_priority(args[0] as isize);
        },
        SYSCALL_TASK_INFO => {
            inner.syscall_times[SYSCALL_TASK_INFO]+=1;
            drop(inner);
            return sys_task_info(args[0] as *mut TaskInfo);
        },
        SYSCALL_SPAWN => {
            inner.syscall_times[SYSCALL_SPAWN]+=1;
            drop(inner);
            return sys_spawn(args[0] as *const u8);
        },
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}
