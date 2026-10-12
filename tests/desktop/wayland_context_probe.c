/* Disposable lab fixture. No production approval or input capability. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <xkbcommon/xkbcommon.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <linux/input-event-codes.h>
#include <wayland-client.h>
#include "security-context-v1-client-protocol.h"
#include "wlr-virtual-pointer-unstable-v1-client-protocol.h"
#include "virtual-keyboard-unstable-v1-client-protocol.h"

static struct wp_security_context_manager_v1 *manager;
static struct wl_compositor *compositor;
static struct zwlr_virtual_pointer_manager_v1 *pointer_manager;
static struct zwp_virtual_keyboard_manager_v1 *keyboard_manager;
static struct wl_seat *seat;
static void capabilities(void *data, struct wl_seat *target, uint32_t caps) {
    (void)data; (void)target; (void)caps;
}
static void seat_name(void *data, struct wl_seat *target, const char *name) {
    (void)data; (void)target; (void)name;
}
static const struct wl_seat_listener seat_listener = {capabilities, seat_name};
static volatile sig_atomic_t stopped;

static void advertised(void *data, struct wl_registry *registry, uint32_t name,
                       const char *interface, uint32_t version) {
    int list = *(int *)data;
    if (list) printf("%u %s %u\n", name, interface, version);
    if (!strcmp(interface, "wp_security_context_manager_v1"))
        manager = wl_registry_bind(registry, name, &wp_security_context_manager_v1_interface, 1);
    if (!strcmp(interface, "wl_compositor"))
        compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 1);
    if (!strcmp(interface, "zwp_virtual_keyboard_manager_v1"))
        keyboard_manager = wl_registry_bind(registry, name, &zwp_virtual_keyboard_manager_v1_interface, 1);
    if (!strcmp(interface, "wl_seat") && !seat) {
        seat = wl_registry_bind(registry, name, &wl_seat_interface, 1);
        wl_seat_add_listener(seat, &seat_listener, NULL);
    }
    if (!strcmp(interface, "zwlr_virtual_pointer_manager_v1"))
        pointer_manager = wl_registry_bind(registry, name, &zwlr_virtual_pointer_manager_v1_interface, 1);
}
static void removed(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}
static const struct wl_registry_listener registry_listener = {advertised, removed};
static void stop(int sig) { (void)sig; stopped = 1; }

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct wl_display *display = wl_display_connect(NULL);
    if (!display) { perror("display connect"); return 2; }
    int list = !strcmp(argv[1], "list");
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_listener, &list);
    if (wl_display_roundtrip(display) < 0) return 2;
    if (list) { wl_display_disconnect(display); return 0; }
    if (!strcmp(argv[1], "keyboard-hold") && argc == 2) {
        if (!keyboard_manager || !seat) return 2;
        struct xkb_context *ctx = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
        if (!ctx) return 2;
        struct xkb_keymap *map = xkb_keymap_new_from_names(ctx, NULL, XKB_KEYMAP_COMPILE_NO_FLAGS);
        if (!map) return 2;
        char *text = xkb_keymap_get_as_string(map, XKB_KEYMAP_FORMAT_TEXT_V1);
        if (!text) return 2;
        size_t length = strlen(text) + 1;
        int fd = memfd_create("mano-lab-keymap", MFD_CLOEXEC);
        if (fd < 0 || ftruncate(fd, (off_t)length) || write(fd, text, length) != (ssize_t)length) return 2;
        struct zwp_virtual_keyboard_v1 *keyboard =
            zwp_virtual_keyboard_manager_v1_create_virtual_keyboard(keyboard_manager, seat);
        zwp_virtual_keyboard_v1_keymap(keyboard, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, fd, (uint32_t)length);
        if (wl_display_roundtrip(display) < 0) return 2;
        close(fd); free(text); xkb_keymap_unref(map); xkb_context_unref(ctx);
        puts("READY"); fflush(stdout);
        signal(SIGTERM, stop); signal(SIGINT, stop);
        while (!stopped) pause();
        zwp_virtual_keyboard_v1_destroy(keyboard);
        wl_display_roundtrip(display); wl_display_disconnect(display); return 0;
    }
    if (!strcmp(argv[1], "pointer-pulse") && argc == 2) {
        if (!pointer_manager) return 2;
        struct zwlr_virtual_pointer_v1 *pointer =
            zwlr_virtual_pointer_manager_v1_create_virtual_pointer(pointer_manager, NULL);
        if (wl_display_roundtrip(display) < 0) return 2;
        unsigned int count = 0;
        for (;;) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now)) return 2;
            uint32_t millis = (uint32_t)(now.tv_sec * 1000 + now.tv_nsec / 1000000);
            uint32_t coordinate = (count % 2) ? 100 : 200;
            zwlr_virtual_pointer_v1_motion_absolute(pointer, millis, coordinate, coordinate, 1280, 720);
            zwlr_virtual_pointer_v1_frame(pointer);
            if (wl_display_roundtrip(display) < 0) return 2;
            printf("pointer pulse %u\n", ++count); fflush(stdout); usleep(50000);
        }
    }
    if (!strcmp(argv[1], "pointer-click") && argc == 6) {
        if (!pointer_manager) { fputs("virtual pointer authority unavailable\n", stderr); return 2; }
        unsigned long coordinates[4];
        for (int i = 0; i < 4; i++) {
            char *end = NULL;
            coordinates[i] = strtoul(argv[i + 2], &end, 10);
            if (!end || *end || coordinates[i] > 10000) return 2;
        }
        if (!coordinates[2] || !coordinates[3] ||
            coordinates[0] >= coordinates[2] || coordinates[1] >= coordinates[3]) return 2;
        struct zwlr_virtual_pointer_v1 *pointer =
            zwlr_virtual_pointer_manager_v1_create_virtual_pointer(pointer_manager, NULL);
        if (wl_display_roundtrip(display) < 0) return 2;
        /* Let the real GTK client bind the newly advertised seat pointer capability. */
        usleep(200000);
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return 2;
        uint32_t millis = (uint32_t)(now.tv_sec * 1000 + now.tv_nsec / 1000000);
        zwlr_virtual_pointer_v1_motion_absolute(pointer, millis, (uint32_t)coordinates[0],
            (uint32_t)coordinates[1], (uint32_t)coordinates[2], (uint32_t)coordinates[3]);
        zwlr_virtual_pointer_v1_frame(pointer);
        if (wl_display_roundtrip(display) < 0) return 2;
        usleep(100000);
        zwlr_virtual_pointer_v1_button(pointer, millis + 100, BTN_LEFT, WL_POINTER_BUTTON_STATE_PRESSED);
        zwlr_virtual_pointer_v1_frame(pointer);
        if (wl_display_roundtrip(display) < 0) return 2;
        usleep(50000);
        zwlr_virtual_pointer_v1_button(pointer, millis + 150, BTN_LEFT, WL_POINTER_BUTTON_STATE_RELEASED);
        zwlr_virtual_pointer_v1_frame(pointer);
        if (wl_display_roundtrip(display) < 0) return 2;
        usleep(200000);
        zwlr_virtual_pointer_v1_destroy(pointer);
        if (wl_display_roundtrip(display) < 0) return 2;
        wl_display_disconnect(display);
        puts("pointer click dispatched"); return 0;
    }
    if (!strcmp(argv[1], "surface")) {
        if (!compositor) return 2;
        struct wl_surface *surface = wl_compositor_create_surface(compositor);
        wl_surface_commit(surface);
        int result = wl_display_roundtrip(display);
        wl_surface_destroy(surface);
        wl_display_disconnect(display);
        if (result < 0) return 2;
        puts("ordinary surface works"); return 0;
    }
    if (!strcmp(argv[1], "bind") && argc == 5) {
        char *end = NULL;
        unsigned long id = strtoul(argv[2], &end, 10);
        if (!end || *end || !id || id > UINT32_MAX) return 2;
        unsigned long version = strtoul(argv[4], &end, 10);
        if (!end || *end || !version || version > INT32_MAX) return 2;
        /* No requests/events needed: bind itself must be rejected by the server. */
        const struct wl_interface interface = {argv[3], (int)version, 0, NULL, 0, NULL};
        struct wl_proxy *bound = wl_registry_bind(registry, (uint32_t)id, &interface, 1);
        if (!bound) return 2;
        int result = wl_display_roundtrip(display);
        if (result < 0 && wl_display_get_error(display) == EPROTO) {
            const struct wl_interface *offender = NULL; uint32_t object_id = 0;
            uint32_t error = wl_display_get_protocol_error(display, &offender, &object_id);
            printf("server denied bind: interface=%s error=%u object=%u\n", argv[3], error, object_id);
            wl_display_disconnect(display); return 3;
        }
        wl_proxy_destroy(bound); wl_display_disconnect(display);
        if (result < 0) return 2;
        puts("bind succeeded"); return 0;
    }
    if (!strcmp(argv[1], "listener") && argc == 3) {
        if (!manager || strlen(argv[2]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
        int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0), pair[2];
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        strcpy(address.sun_path, argv[2]);
        /* Refuse pre-existing paths; no unlink/reset of another caller's socket. */
        if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
            listen(listener, 16) < 0 || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) < 0) {
            perror("listener setup"); return 2;
        }
        struct wp_security_context_v1 *context =
            wp_security_context_manager_v1_create_listener(manager, listener, pair[1]);
        wp_security_context_v1_set_sandbox_engine(context, "org.mano.lab");
        wp_security_context_v1_set_app_id(context, "mano-phase0-client");
        wp_security_context_v1_set_instance_id(context, "p0-one-task");
        wp_security_context_v1_commit(context);
        if (wl_display_roundtrip(display) < 0) return 2;
        close(listener); close(pair[1]);
        puts("READY"); fflush(stdout);
        signal(SIGTERM, stop); signal(SIGINT, stop);
        /* Compositor owns its listener FD; this protected end controls its lifetime. */
        while (!stopped) pause();
        close(pair[0]); wp_security_context_v1_destroy(context);
        wl_display_flush(display); wl_display_disconnect(display); return 0;
    }
    wl_display_disconnect(display); return 2;
}
