#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include <stddef.h>
#include <string.h>

enum {
    KPEXEC_AUTHORIZED = 0,
    KPEXEC_AUTH_DENIED = 1,
    KPEXEC_AUTH_UNAVAILABLE = 2,
    KPEXEC_AUTH_INTERNAL = 3,
};

static void copy_error(char *buffer, size_t capacity, NSError *error) {
    if (buffer == NULL || capacity == 0) {
        return;
    }
    NSString *description = error.localizedDescription ?: @"unknown LocalAuthentication error";
    const char *utf8 = description.UTF8String;
    if (utf8 == NULL) {
        utf8 = "unknown LocalAuthentication error";
    }
    strlcpy(buffer, utf8, capacity);
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
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

        if (authorized) {
            return KPEXEC_AUTHORIZED;
        }
        copy_error(error_buffer, error_capacity, evaluation_error);
        return is_unavailable_error(evaluation_error)
                   ? KPEXEC_AUTH_UNAVAILABLE
                   : KPEXEC_AUTH_DENIED;
    }
}
