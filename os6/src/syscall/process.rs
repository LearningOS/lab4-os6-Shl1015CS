//! Process management syscalls

use crate::mm::{translated_refmut, translated_ref, translated_str,frame_alloc};
use crate::task::{
    add_task, current_task, current_user_token, exit_current_and_run_next,
    suspend_current_and_run_next, TaskStatus,
};
use crate::fs::{open_file, OpenFlags};
use crate::timer::get_time_us;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::config::MAX_SYSCALL_NUM;
use alloc::string::String;
use crate::mm::address::{VirtAddr};
use crate::mm::page_table::{PTEFlags, PageTable};
use crate::config::{PAGE_SIZE,BIG_STRIDE};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    debug!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    current_task().unwrap().pid.0 as isize
}

/// Syscall Fork which returns 0 for child process and child_pid for parent process
pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

/// Syscall Exec which accepts the elf path
pub fn sys_exec(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        task.exec(all_data.as_slice());
        0
    } else {
        -1
    }
}


/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    // find a child process

    // ---- access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB lock exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after removing from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child TCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB lock automatically
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    let _us = get_time_us();
    let virtual_address=VirtAddr::from(_ts as usize);
    let page_table=PageTable::from_token(current_user_token());
    let ppn=page_table.translate(virtual_address.floor()).unwrap().ppn().0;
    let physical_address=ppn<<12|virtual_address.page_offset();
    unsafe {
        *(physical_address as *mut TimeVal) = TimeVal {
            sec: _us / 1_000_000,
            usec: _us % 1_000_000,
        };
    }
    0
}

// YOUR JOB: 引入虚地址后重写 sys_task_info
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let virtual_address=VirtAddr::from(ti as usize);
    let page_table=PageTable::from_token(current_user_token());
    let ppn=page_table.translate(virtual_address.floor()).unwrap().ppn().0;
    let physical_address=ppn<<12|virtual_address.page_offset();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    unsafe{
        *(physical_address as *mut TaskInfo)=TaskInfo{
            // Change the status of current `Running` task into `Exited`.
            status:TaskStatus::Running,
            syscall_times: inner.syscall_times,
            time: get_time_us()/1_000-inner.start_time/1_000,
        };
    }
    0
}

// YOUR JOB: 实现sys_set_priority，为任务添加优先级
pub fn sys_set_priority(_prio: isize) -> isize {
    // syscall ID：140
    // 设置当前进程优先级为 prio
    // 参数：prio 进程优先级，要求 prio >= 2
    // 返回值：如果输入合法则返回 prio，否则返回 -1
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if _prio >= 2 {
        inner.priority = _prio as usize;
        inner.pass=BIG_STRIDE/inner.priority;
        drop(inner);
        return _prio;
    } else {
        return -1;
    }
}
// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    if _start&0xfff!=0 { return -1; }
    if _port&!0x7!=0 { return -1; }
    if _port&0x7==0 { return -1; }
    let mut page_table=PageTable::from_token(current_user_token());
    let pages=(_len+PAGE_SIZE-1)/PAGE_SIZE; // pages=ceil(_len/PAGE_SIZE)
    for i in 0..pages{
        let vpn=VirtAddr::from(_start+i*PAGE_SIZE).floor();
        let page_table_entry=page_table.translate(vpn);
        if !page_table_entry.is_none(){
            if page_table_entry.unwrap().is_valid(){
                return -1;
            }
        }
    }
    for i in 0..pages{
        // 物理内存不足, 注意因为这种情况造成的分配失败，没有回收已经分配过的内存
        let new_physical_page=frame_alloc();
        if new_physical_page.is_none(){
            return -1;
        }
        let vpn=VirtAddr::from(_start+i*PAGE_SIZE).floor();
        let ppn=new_physical_page.unwrap().ppn;
        let mut flags=PTEFlags::U;
        if _port&0x1==0x1 { flags=flags|PTEFlags::R; }
        if _port&0x2==0x2 { flags=flags|PTEFlags::W; }
        if _port&0x4==0x4 { flags=flags|PTEFlags::X; }
        page_table.map(vpn,ppn,flags);
    }
    0
}

pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    if _start&0xfff!=0{
        return -1;
    }
    let mut page_table=PageTable::from_token(current_user_token());
    let pages=(_len+PAGE_SIZE-1)/PAGE_SIZE;
    for i in 0..pages {
        let vpn=VirtAddr::from(_start+i*PAGE_SIZE).floor();
        let page_table_entry=page_table.translate(vpn);
        if page_table_entry.is_none(){
            return -1;
        }
        if !(page_table_entry.unwrap().is_valid()){
            return -1;
        }
    }
    for i in 0..pages{
        let vpn=VirtAddr::from(_start+i*PAGE_SIZE).floor();
        page_table.unmap(vpn);
    }
    0
}

//
// YOUR JOB: 实现 sys_spawn 系统调用
// ALERT: 注意在实现 SPAWN 时不需要复制父进程地址空间，SPAWN != FORK + EXEC 
pub fn sys_spawn(_path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, _path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        let new_task=task.spawn(all_data.as_slice());
        let new_pid = new_task.pid.0;
        let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
        trap_cx.x[10] = 0;
        add_task(new_task);
        return new_pid as isize;
    } else {
        return -1;
    }
}

