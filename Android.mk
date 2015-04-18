LOCAL_PATH:= $(call my-dir)
# prebuilt libssl
include $(CLEAR_VARS)

LOCAL_MODULE := ssl
LOCAL_SRC_FILES := ../../android-openssl/libs/$(TARGET_ARCH_ABI)/libssl.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../include/

include $(PREBUILT_SHARED_LIBRARY)

# prebuilt libcrypto
include $(CLEAR_VARS)

LOCAL_MODULE := crypto
LOCAL_SRC_FILES := ../../android-openssl/libs/$(TARGET_ARCH_ABI)/libcrypto.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../include/

include $(PREBUILT_SHARED_LIBRARY)

###################### libssh ######################
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    authfd.c authfile.c bufaux.c bufbn.c buffer.c \
    canohost.c channels.c cipher.c cipher-aes.c \
    cipher-aesctr.c \
    cipher-bf1.c cipher-ctr.c cipher-3des1.c cleanup.c \
    compat.c crc32.c deattack.c fatal.c hostfile.c \
    digest-openssl.c \
    hmac.c \
    hash.c \
    bitmap.c \
    blocks.c \
    cipher-chachapoly.c \
    chacha.c \
    ed25519.c \
    fe25519.c \
    ge25519.c \
    kexc25519.c \
    kexc25519c.c \
    kexc25519s.c \
    krl.c \
    poly1305.c \
    sc25519.c \
    smult_curve25519_ref.c \
    ssh-ed25519.c \
    log.c match.c md-sha256.c moduli.c nchan.c packet.c \
    readpass.c rsa.c ttymodes.c xmalloc.c addrmatch.c \
    atomicio.c key.c dispatch.c kex.c mac.c \
    uidswap.c \
    uuencode.c misc.c \
    monitor_fdpass.c rijndael.c ssh-dss.c ssh-ecdsa.c ssh-rsa.c dh.c \
    kexdh.c kexgex.c kexdhc.c kexgexc.c bufec.c kexecdh.c kexecdhc.c \
    msg.c progressmeter.c dns.c entropy.c gss-genr.c umac.c \
    umac128.c \
    opacket.c \
    sshbuf.c \
    sshbuf-getput-basic.c \
    sshbuf-getput-crypto.c \
    sshbuf-misc.c \
    ssherr.c \
    sshkey.c \
    verify.c \
    ssh-pkcs11.c roaming_dummy.c \
    openbsd-compat/arc4random.c \
    openbsd-compat/strtonum.c openbsd-compat/bsd-misc.c \
    openbsd-compat/timingsafe_bcmp.c openbsd-compat/bsd-getpeereid.c \
    openbsd-compat/readpassphrase.c openbsd-compat/vis.c \
    openbsd-compat/port-tun.c openbsd-compat/setproctitle.c \
    openbsd-compat/bsd-closefrom.c  openbsd-compat/getopt_long.c \
    openbsd-compat/rresvport.c openbsd-compat/bindresvport.c \
    openbsd-compat/xmmap.c \
    openbsd-compat/port-linux.c openbsd-compat/strmode.c \
    openbsd-compat/bsd-openpty.c \
    openbsd-compat/explicit_bzero.c \
    openbsd-compat/blowfish.c \
    openbsd-compat/bcrypt_pbkdf.c \
    openbsd-compat/fmt_scaled.c \
    openbsd-compat/pwcache.c openbsd-compat/glob.c \
    openbsd-compat/getrrsetbyname-ldns.c \
    openbsd-compat/bsd-statvfs.c \
    openbsd-compat/reallocarray.c \
    openbsd-compat/openssl-compat.c

#    acss cipher-acss jpake.c schnorr.c
#    openbsd-compat/getrrsetbyname.c
#    openbsd-compat/xcrypt.c 
# fixme hharte: openbsd-compat/getrrsetbyname.c

# needs to be fixed: openbsd-compat/bsd-statvfs.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../android-openssl/jni/include/
LOCAL_C_INCLUDES += $(LOCAL_PATH)/openbsd-compat
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..

LOCAL_SHARED_LIBRARIES += ssl crypto
LOCAL_LDLIBS := -lz -ldl

LOCAL_MODULE := libssh

LOCAL_CFLAGS+=-O3

include $(BUILD_SHARED_LIBRARY)

###################### ssh ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ssh.c readconf.c clientloop.c sshtty.c \
    sshconnect.c sshconnect1.c sshconnect2.c mux.c \
    roaming_common.c roaming_client.c

LOCAL_MODULE := client-ssh

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../android-openssl/jni/include/
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../..

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### sftp ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    sftp.c sftp-client.c sftp-common.c sftp-glob.c progressmeter.c

LOCAL_MODULE := sftp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../android-openssl/jni/include/

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### scp ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    scp.c progressmeter.c bufaux.c

LOCAL_MODULE := scp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../android-openssl/jni/include/

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### sshd ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    sshd.c auth-rhosts.c auth-rsa.c auth-rh-rsa.c \
	krl.c \
	audit.c audit-bsm.c audit-linux.c platform.c \
	sshpty.c sshlogin.c servconf.c serverloop.c \
	auth.c auth1.c auth2.c auth-options.c session.c \
	auth-chall.c auth2-chall.c groupaccess.c \
	auth-skey.c auth-bsdauth.c auth2-hostbased.c auth2-kbdint.c \
	auth2-none.c auth2-passwd.c auth2-pubkey.c \
	monitor_mm.c monitor.c monitor_wrap.c kexdhs.c kexgexs.c kexecdhs.c \
	auth-krb5.c \
	auth2-gss.c gss-serv.c gss-serv-krb5.c \
	loginrec.c auth-pam.c auth-shadow.c auth-sia.c md5crypt.c \
	sftp-server.c sftp-common.c \
	roaming_common.c roaming_serv.c \
	sandbox-null.c sandbox-rlimit.c sandbox-systrace.c sandbox-darwin.c

# auth-passwd.c auth2-jpake.c

LOCAL_MODULE := sshd

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../android-openssl/jni/include/

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### ssh-keygen ######################

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
    ssh-keygen.c \
    krl.c

LOCAL_MODULE := ssh-keygen

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../android-openssl/jni/include/

LOCAL_SHARED_LIBRARIES += libssh libssl libcrypto libdl libz

include $(BUILD_EXECUTABLE)

###################### sshd_config ######################

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := sshd_config
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/ssh
LOCAL_SRC_FILES := sshd_config.android
include $(BUILD_PREBUILT)

###################### start-ssh ######################

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := start-ssh
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := start-ssh
include $(BUILD_PREBUILT)
