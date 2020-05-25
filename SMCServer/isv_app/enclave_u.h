#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"
#include "time.h"
#include "inc/stat.h"
#include "sys/uio.h"
#include "inc/stat.h"
#include "inc/dirent.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef U_THREAD_SET_EVENT_OCALL_DEFINED__
#define U_THREAD_SET_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_thread_set_event_ocall, (int* error, const void* tcs));
#endif
#ifndef U_THREAD_WAIT_EVENT_OCALL_DEFINED__
#define U_THREAD_WAIT_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_thread_wait_event_ocall, (int* error, const void* tcs, const struct timespec* timeout));
#endif
#ifndef U_THREAD_SET_MULTIPLE_EVENTS_OCALL_DEFINED__
#define U_THREAD_SET_MULTIPLE_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_thread_set_multiple_events_ocall, (int* error, const void** tcss, int total));
#endif
#ifndef U_THREAD_SETWAIT_EVENTS_OCALL_DEFINED__
#define U_THREAD_SETWAIT_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_thread_setwait_events_ocall, (int* error, const void* waiter_tcs, const void* self_tcs, const struct timespec* timeout));
#endif
#ifndef U_CLOCK_GETTIME_OCALL_DEFINED__
#define U_CLOCK_GETTIME_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_clock_gettime_ocall, (int* error, int clk_id, struct timespec* tp));
#endif
#ifndef U_READ_OCALL_DEFINED__
#define U_READ_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_read_ocall, (int* error, int fd, void* buf, size_t count));
#endif
#ifndef U_PREAD64_OCALL_DEFINED__
#define U_PREAD64_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_pread64_ocall, (int* error, int fd, void* buf, size_t count, int64_t offset));
#endif
#ifndef U_READV_OCALL_DEFINED__
#define U_READV_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_readv_ocall, (int* error, int fd, const struct iovec* iov, int iovcnt));
#endif
#ifndef U_PREADV64_OCALL_DEFINED__
#define U_PREADV64_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_preadv64_ocall, (int* error, int fd, const struct iovec* iov, int iovcnt, int64_t offset));
#endif
#ifndef U_WRITE_OCALL_DEFINED__
#define U_WRITE_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_write_ocall, (int* error, int fd, const void* buf, size_t count));
#endif
#ifndef U_PWRITE64_OCALL_DEFINED__
#define U_PWRITE64_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_pwrite64_ocall, (int* error, int fd, const void* buf, size_t count, int64_t offset));
#endif
#ifndef U_WRITEV_OCALL_DEFINED__
#define U_WRITEV_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_writev_ocall, (int* error, int fd, const struct iovec* iov, int iovcnt));
#endif
#ifndef U_PWRITEV64_OCALL_DEFINED__
#define U_PWRITEV64_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_pwritev64_ocall, (int* error, int fd, const struct iovec* iov, int iovcnt, int64_t offset));
#endif
#ifndef U_FCNTL_ARG0_OCALL_DEFINED__
#define U_FCNTL_ARG0_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fcntl_arg0_ocall, (int* error, int fd, int cmd));
#endif
#ifndef U_FCNTL_ARG1_OCALL_DEFINED__
#define U_FCNTL_ARG1_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fcntl_arg1_ocall, (int* error, int fd, int cmd, int arg));
#endif
#ifndef U_IOCTL_ARG0_OCALL_DEFINED__
#define U_IOCTL_ARG0_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_ioctl_arg0_ocall, (int* error, int fd, int request));
#endif
#ifndef U_IOCTL_ARG1_OCALL_DEFINED__
#define U_IOCTL_ARG1_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_ioctl_arg1_ocall, (int* error, int fd, int request, int* arg));
#endif
#ifndef U_CLOSE_OCALL_DEFINED__
#define U_CLOSE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_close_ocall, (int* error, int fd));
#endif
#ifndef U_MALLOC_OCALL_DEFINED__
#define U_MALLOC_OCALL_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_malloc_ocall, (int* error, size_t size));
#endif
#ifndef U_FREE_OCALL_DEFINED__
#define U_FREE_OCALL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_free_ocall, (void* p));
#endif
#ifndef U_MMAP_OCALL_DEFINED__
#define U_MMAP_OCALL_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_mmap_ocall, (int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset));
#endif
#ifndef U_MUNMAP_OCALL_DEFINED__
#define U_MUNMAP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_munmap_ocall, (int* error, void* start, size_t length));
#endif
#ifndef U_MSYNC_OCALL_DEFINED__
#define U_MSYNC_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_msync_ocall, (int* error, void* addr, size_t length, int flags));
#endif
#ifndef U_MPROTECT_OCALL_DEFINED__
#define U_MPROTECT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_mprotect_ocall, (int* error, void* addr, size_t length, int prot));
#endif
#ifndef U_OPEN_OCALL_DEFINED__
#define U_OPEN_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_open_ocall, (int* error, const char* pathname, int flags));
#endif
#ifndef U_OPEN64_OCALL_DEFINED__
#define U_OPEN64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_open64_ocall, (int* error, const char* path, int oflag, int mode));
#endif
#ifndef U_FSTAT_OCALL_DEFINED__
#define U_FSTAT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fstat_ocall, (int* error, int fd, struct stat_t* buf));
#endif
#ifndef U_FSTAT64_OCALL_DEFINED__
#define U_FSTAT64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fstat64_ocall, (int* error, int fd, struct stat64_t* buf));
#endif
#ifndef U_STAT_OCALL_DEFINED__
#define U_STAT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_stat_ocall, (int* error, const char* path, struct stat_t* buf));
#endif
#ifndef U_STAT64_OCALL_DEFINED__
#define U_STAT64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_stat64_ocall, (int* error, const char* path, struct stat64_t* buf));
#endif
#ifndef U_LSTAT_OCALL_DEFINED__
#define U_LSTAT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_lstat_ocall, (int* error, const char* path, struct stat_t* buf));
#endif
#ifndef U_LSTAT64_OCALL_DEFINED__
#define U_LSTAT64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_lstat64_ocall, (int* error, const char* path, struct stat64_t* buf));
#endif
#ifndef U_LSEEK_OCALL_DEFINED__
#define U_LSEEK_OCALL_DEFINED__
uint64_t SGX_UBRIDGE(SGX_NOCONVENTION, u_lseek_ocall, (int* error, int fd, int64_t offset, int whence));
#endif
#ifndef U_LSEEK64_OCALL_DEFINED__
#define U_LSEEK64_OCALL_DEFINED__
int64_t SGX_UBRIDGE(SGX_NOCONVENTION, u_lseek64_ocall, (int* error, int fd, int64_t offset, int whence));
#endif
#ifndef U_FTRUNCATE_OCALL_DEFINED__
#define U_FTRUNCATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_ftruncate_ocall, (int* error, int fd, int64_t length));
#endif
#ifndef U_FTRUNCATE64_OCALL_DEFINED__
#define U_FTRUNCATE64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_ftruncate64_ocall, (int* error, int fd, int64_t length));
#endif
#ifndef U_TRUNCATE_OCALL_DEFINED__
#define U_TRUNCATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_truncate_ocall, (int* error, const char* path, int64_t length));
#endif
#ifndef U_TRUNCATE64_OCALL_DEFINED__
#define U_TRUNCATE64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_truncate64_ocall, (int* error, const char* path, int64_t length));
#endif
#ifndef U_FSYNC_OCALL_DEFINED__
#define U_FSYNC_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fsync_ocall, (int* error, int fd));
#endif
#ifndef U_FDATASYNC_OCALL_DEFINED__
#define U_FDATASYNC_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fdatasync_ocall, (int* error, int fd));
#endif
#ifndef U_FCHMOD_OCALL_DEFINED__
#define U_FCHMOD_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fchmod_ocall, (int* error, int fd, uint32_t mode));
#endif
#ifndef U_UNLINK_OCALL_DEFINED__
#define U_UNLINK_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_unlink_ocall, (int* error, const char* pathname));
#endif
#ifndef U_LINK_OCALL_DEFINED__
#define U_LINK_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_link_ocall, (int* error, const char* oldpath, const char* newpath));
#endif
#ifndef U_RENAME_OCALL_DEFINED__
#define U_RENAME_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_rename_ocall, (int* error, const char* oldpath, const char* newpath));
#endif
#ifndef U_CHMOD_OCALL_DEFINED__
#define U_CHMOD_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_chmod_ocall, (int* error, const char* path, uint32_t mode));
#endif
#ifndef U_READLINK_OCALL_DEFINED__
#define U_READLINK_OCALL_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_readlink_ocall, (int* error, const char* path, char* buf, size_t bufsz));
#endif
#ifndef U_SYMLINK_OCALL_DEFINED__
#define U_SYMLINK_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_symlink_ocall, (int* error, const char* path1, const char* path2));
#endif
#ifndef U_REALPATH_OCALL_DEFINED__
#define U_REALPATH_OCALL_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_realpath_ocall, (int* error, const char* pathname));
#endif
#ifndef U_MKDIR_OCALL_DEFINED__
#define U_MKDIR_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_mkdir_ocall, (int* error, const char* pathname, uint32_t mode));
#endif
#ifndef U_RMDIR_OCALL_DEFINED__
#define U_RMDIR_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_rmdir_ocall, (int* error, const char* pathname));
#endif
#ifndef U_OPENDIR_OCALL_DEFINED__
#define U_OPENDIR_OCALL_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_opendir_ocall, (int* error, const char* pathname));
#endif
#ifndef U_READDIR64_R_OCALL_DEFINED__
#define U_READDIR64_R_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_readdir64_r_ocall, (void* dirp, struct dirent64_t* entry, struct dirent64_t** result));
#endif
#ifndef U_CLOSEDIR_OCALL_DEFINED__
#define U_CLOSEDIR_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_closedir_ocall, (int* error, void* dirp));
#endif
#ifndef U_DIRFD_OCALL_DEFINED__
#define U_DIRFD_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_dirfd_ocall, (int* error, void* dirp));
#endif
#ifndef U_FSTATAT64_OCALL_DEFINED__
#define U_FSTATAT64_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fstatat64_ocall, (int* error, int dirfd, const char* pathname, struct stat64_t* buf, int flags));
#endif

sgx_status_t initialize(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t salt[32]);
sgx_status_t uploadCentralData(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* filedata, size_t file_size);
sgx_status_t uninitialize(sgx_enclave_id_t eid);
sgx_status_t remote_attestation_mock(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t token[32], uint8_t sk[16]);
sgx_status_t judge_contact(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t session_token[32], uint8_t encrypted_secret_key[16], uint8_t secret_key_gcm_tag[16], uint8_t* encrypted_history_data, size_t toal_size, uint8_t* gcm_tag, size_t gcm_tag_total_size, size_t* size_list, size_t data_num, uint8_t risk_level[1], uint8_t result_mac[16]);
sgx_status_t store_infected_data(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t session_token[32], uint8_t encrypted_secret_key[16], uint8_t secret_key_gcm_tag[16], uint8_t* encrypted_history_data, size_t toal_size, uint8_t* gcm_tag, size_t gcm_tag_total_size, size_t* size_list, size_t data_num);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);
sgx_status_t t_global_init_ecall(sgx_enclave_id_t eid, uint64_t id, const uint8_t* path, size_t len);
sgx_status_t t_global_exit_ecall(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
