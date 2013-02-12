#include <stdint.h>

%%{
    machine Kospi;
    alphtype unsigned char;
    write data;

    # Define a parser for Kospi 200 UDP quotes

    # Values are transmitted as ASCII digits. It's a good idea to verify this at runtime, but
    # this check is not free. Replacing each 'digit' with 'any' will significantly reduce
    # the size of the generated function and improve runtime performance.
    price         = (digit @{ scratch *= 10; scratch += (fc - '0'); }){5} >{ scratch = 0; };
    quantity      = (digit @{ scratch *= 10; scratch += (fc - '0'); }){7} >{ scratch = 0; };

    # Quote packet
    data_type     = 'B6';
    info_type     = '03';
    market_type   = '4';

    # The issue code appears to be in the form 'KRxxxxFxxxxx'
    issue_code1   = (digit @{ scratch *= 10; scratch += (fc - '0'); }){4} >{ scratch = 0; };
    issue_code2   = (digit @{ scratch *= 10; scratch += (fc - '0'); }){5} >{ scratch = 0; };
    issue_code    = 'KR' issue_code1 %{ issue_code1 = scratch; } 'F' issue_code2 %{ issue_code2 = scratch; };
    issue_seq_no  = any{3};

    market_status = any{2};
    total_bid_vol = quantity;
    total_ask_vol = quantity;

    # The results are passed as an unboxed tuple. These are split between the first
    # six (R1-R6) registers and the remainder lives on the stack. To make it conventient
    # and relatively quick, we will store the parsing results directly in the correct
    # stack offset... if this isn't done it will cause the register allocator to spill
    # these to the C stack and get reloaded later.
    bid1          = price %{ sp[-10] = scratch; } quantity %{ sp[-9] = scratch; };
    bid2          = price %{ sp[ -8] = scratch; } quantity %{ sp[-7] = scratch; };
    bid3          = price %{ sp[ -6] = scratch; } quantity %{ sp[-5] = scratch; };
    bid4          = price %{ sp[ -4] = scratch; } quantity %{ sp[-3] = scratch; };
    bid5          = price %{ sp[ -2] = scratch; } quantity %{ sp[-1] = scratch; };
    bids          = bid1 bid2 bid3 bid4 bid5;

    ask1          = price %{ sp[-12] = scratch; } quantity %{ sp[-11] = scratch; };
    ask2          = price %{ sp[-14] = scratch; } quantity %{ sp[-13] = scratch; };
    ask3          = price %{ sp[-16] = scratch; } quantity %{ sp[-15] = scratch; };
    ask4          = price %{ sp[-18] = scratch; } quantity %{ sp[-17] = scratch; };
    ask5          = price %{ sp[-20] = scratch; } quantity %{ sp[-19] = scratch; };
    asks          = ask1 ask2 ask3 ask4 ask5;

    ignore        = any{50};

    hour1         = digit >{ quote_time = fc - '0'; };
    hour2         = digit >{ quote_time *= 10; quote_time += fc - '0'; };
    minute1       = digit >{ quote_time *= 60; quote_time += fc - '0'; };
    minute2       = digit >{ quote_time *= 10; quote_time += fc - '0'; };
    second1       = digit >{ quote_time *= 60; quote_time += fc - '0'; };
    second2       = digit >{ quote_time *= 10; quote_time += fc - '0'; };
    usec1         = digit >{ quote_time *= 10; quote_time += fc - '0'; };
    usec2         = digit >{ quote_time *= 10; quote_time += fc - '0'; };
    quote_time    = hour1 hour2 minute1 minute2 second1 second2 usec1 usec2;

    eom           = 0xFF;

    # Inspect the packet headers, verify UDP protocol (0x11) and port 15515 (0x3C9B) or 15516 (0x3C9C)
    header        = any{23} 0x11 any{12} 0x3C (0x9B | 0x9C) any{4};
    # header        = any{42};

    # define a quote packet including the IP/UDP header
    quote = header data_type info_type market_type issue_code issue_seq_no market_status total_bid_vol bids total_ask_vol asks ignore quote_time eom;

    main := quote;
}%%

// define a function pointer type that matches the STG calling convention
typedef void (*HsCall)(int64_t*, int64_t*, int64_t*, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t*, float, float, float, float, double, double);

static inline void
returnError(
    HsCall fun,
    int64_t* restrict baseReg,
    int64_t* restrict sp,
    int64_t* restrict hp,
    int64_t* restrict spLim,
    int64_t status)
{
    // create undefined variables, clang will emit these as a llvm undef literal
    const int64_t iUndef;
    const float fUndef;
    const double dUndef;

    return fun(
        baseReg,
        sp,
        hp,
        status,
        iUndef,
        iUndef,
        iUndef,
        iUndef,
        iUndef,
        spLim,
        fUndef,
        fUndef,
        fUndef,
        fUndef,
        dUndef,
        dUndef);
}

extern void
QuoteParser_run(
    int64_t* restrict baseReg,
    int64_t* restrict sp,
    int64_t* restrict hp,
    const uint8_t* restrict buffer, // R1
    int64_t length, // R2
    int64_t r3,
    int64_t r4,
    int64_t r5,
    int64_t r6,
    int64_t* restrict spLim,
    float f1,
    float f2,
    float f3,
    float f4,
    double d1,
    double d2)
{
    int cs;
    %% write init;

    // create undefined variables, clang will emit these as a llvm undef literal
    const int64_t iUndef;
    const float fUndef;
    const double dUndef;

    const uint8_t* p = buffer;
    const uint8_t* pe = &buffer[length];

    // XXX: need to check the stack limit
    HsCall fun = (HsCall)sp[0];

    // allocate enough stack space for the quote data, this needs to line up
    // exactly with the primop return type in Main.hs
    int64_t* updated_stack = &sp[-20];

    // fixing the length disables incremental parsing and generates optimized code that
    // loads values by offset out of the source buffer, rather than incrementing a pointer
    if (__builtin_expect(length != 257, 0)) // 215+42 .. including ip/udp headers
    {
        return returnError(fun, baseReg, updated_stack, hp, spLim, -3);
    }

    // storage for values passed in register back to Haskell
    uint64_t issue_code1;
    uint64_t issue_code2;
    uint64_t quote_time;

    // shared storage space for integer parsing
    uint64_t scratch;

    // run the parser
    %% write exec;

    // the machine has completed
    if (cs == Kospi_first_final)
    {
        return fun(
            baseReg,
            updated_stack,
            hp,
            0,
            quote_time,
            issue_code1,
            issue_code2,
            iUndef, // we're wasting some registers for clarity.
            iUndef,
            spLim,
            fUndef,
            fUndef,
            fUndef,
            fUndef,
            dUndef,
            dUndef);
    }
    // validation failed, this is not the packet we're looking for
    else if (cs == Kospi_error)
    {
        return returnError(fun, baseReg, updated_stack, hp, spLim, -1);
    }
    // otherwise it's a truncated packet
    else
    {
        return returnError(fun, baseReg, updated_stack, hp, spLim, -2);
    }
}
