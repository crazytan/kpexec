#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/AuthSession.h>
#import <dispatch/dispatch.h>

#include <stddef.h>
#include <string.h>

enum {
    KPEXEC_AUTHORIZED = 0,
    KPEXEC_AUTH_DENIED = 1,
    KPEXEC_AUTH_UNAVAILABLE = 2,
    KPEXEC_AUTH_INTERNAL = 3,
};

static void copy_message(char *buffer, size_t capacity, NSString *message) {
    if (buffer == NULL || capacity == 0) {
        return;
    }
    const char *utf8 = message.UTF8String;
    if (utf8 == NULL) {
        utf8 = "unknown LocalAuthentication error";
    }
    strlcpy(buffer, utf8, capacity);
}

static void copy_error(char *buffer, size_t capacity, NSError *error) {
    if (error == nil) {
        copy_message(buffer, capacity, @"unknown LocalAuthentication error");
        return;
    }
    NSString *message = [NSString
        stringWithFormat:@"%@ code=%ld: %@",
                         error.domain ?: @"unknown-domain",
                         (long)error.code,
                         error.localizedDescription ?: @"no description"];
    copy_message(buffer, capacity, message);
}

static BOOL is_unavailable_error(NSError *error) {
    if (error == nil || ![error.domain isEqualToString:LAErrorDomain]) {
        return NO;
    }
    switch ((LAError)error.code) {
    case LAErrorBiometryNotAvailable:
    case LAErrorBiometryNotEnrolled:
    case LAErrorPasscodeNotSet:
    case LAErrorNotInteractive:
        return YES;
    default:
        return NO;
    }
}

// Synchronous, narrow C boundary used by Rust. The LocalAuthentication reply
// remains asynchronous internally; the command waits for a definitive result
// before dispatch is allowed to reach any mutating handler.
int kpexec_authorize_user_presence(const char *reason_utf8,
                                   char *error_buffer,
                                   size_t error_capacity) {
    @autoreleasepool {
        if (reason_utf8 == NULL) {
            return KPEXEC_AUTH_INTERNAL;
        }
        NSString *reason = [NSString stringWithUTF8String:reason_utf8];
        if (reason == nil || reason.length == 0) {
            return KPEXEC_AUTH_INTERNAL;
        }

        // LocalAuthentication can route UI from an SSH process to the active
        // console session. Reject remote and non-graphical security sessions
        // before creating an LAContext so a headless caller cannot summon a
        // misleading approval sheet. These are kernel Security-session/audit
        // attributes inherited across fork/exec, not spoofable SSH environment
        // variables.
        SessionAttributeBits session_attributes = 0;
        OSStatus session_status = SessionGetInfo(callerSecuritySession,
                                                  NULL,
                                                  &session_attributes);
        if (session_status != errSessionSuccess) {
            NSString *message = [NSString
                stringWithFormat:@"Security session inspection failed: OSStatus %d",
                                 (int)session_status];
            copy_message(error_buffer, error_capacity, message);
            return KPEXEC_AUTH_UNAVAILABLE;
        }
        if ((session_attributes & sessionIsRemote) != 0) {
            copy_message(error_buffer,
                         error_capacity,
                         @"LocalAuthentication is disabled for remote security sessions");
            return KPEXEC_AUTH_UNAVAILABLE;
        }
        if ((session_attributes & sessionHasGraphicAccess) == 0) {
            copy_message(error_buffer,
                         error_capacity,
                         @"LocalAuthentication requires a graphical security session");
            return KPEXEC_AUTH_UNAVAILABLE;
        }

        LAContext *context = [[LAContext alloc] init];
        NSError *capability_error = nil;
        LAPolicy policy = LAPolicyDeviceOwnerAuthentication;
        if (![context canEvaluatePolicy:policy error:&capability_error]) {
            copy_error(error_buffer, error_capacity, capability_error);
            return KPEXEC_AUTH_UNAVAILABLE;
        }

        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
        __block BOOL authorized = NO;
        __block NSError *evaluation_error = nil;
        [context evaluatePolicy:policy
                localizedReason:reason
                          reply:^(BOOL success, NSError *error) {
            authorized = success;
            evaluation_error = error;
            dispatch_semaphore_signal(semaphore);
        }];
        // A framework callback must not be able to hang a CLI mutation forever.
        // Invalidation is fail-closed; a late callback retains its captured
        // state under ARC and is safe after this function returns.
        dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 120 * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(semaphore, deadline) != 0) {
            [context invalidate];
            copy_message(error_buffer,
                         error_capacity,
                         @"LocalAuthentication timeout after 120 seconds");
            return KPEXEC_AUTH_UNAVAILABLE;
        }

        if (authorized) {
            return KPEXEC_AUTHORIZED;
        }
        copy_error(error_buffer, error_capacity, evaluation_error);
        return is_unavailable_error(evaluation_error)
                   ? KPEXEC_AUTH_UNAVAILABLE
                   : KPEXEC_AUTH_DENIED;
    }
}
