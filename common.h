/* Display functions */
extern void
start(const char *, ...)
__attribute__ ((format (printf, 1, 2)));

extern void
end(const char *, ...)
__attribute__ ((format (printf, 1, 2)));

extern void
fail(const char *, ...)
__attribute__ ((format (printf, 1, 2)));

extern void
warn(const char *, ...)
__attribute__ ((format (printf, 1, 2)));
