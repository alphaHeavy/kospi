#include <stdlib.h>
#include <stdint.h>

%%{
    machine Kospi;
    alphtype unsigned char;
    write data;
}%%

%%{
    # Assume price/quantity fields are ASCII digits. Change the 'any' to 'digit' to check at runtime.
    price         = (any @{ scratch *= 10; scratch += (fc - '0'); }){5} >{ scratch = 0; };
    quantity      = (any @{ scratch *= 10; scratch += (fc - '0'); }){7} >{ scratch = 0; };
    issue_code1   = (digit @{ scratch *= 10; scratch += (fc - '0'); }){4} >{ scratch = 0; };
    issue_code2   = (digit @{ scratch *= 10; scratch += (fc - '0'); }){5} >{ scratch = 0; };

    # File header
    magic_number  = 0xD4 0xC3 0xB2 0xA1;
    version_major = 0x02 0x00;
    version_minor = 0x04 0x00;
    thiszone = 0x00{4};
    sigflags = 0x00{4};
    snaplen  = 0xFF 0xFF 0x00 0x00;
    network  = 0x01 0x00 0x00 0x00; # ethernet
    pcap_hdr = magic_number version_major version_minor thiszone sigflags snaplen network;

    # Packet header
    ts_sec   = any{4};
    ts_usec  = any{4};
    incl_len = any{4};
    orig_len = any{4};
    pcaprec_hdr = ts_sec ts_usec incl_len orig_len;

    # Quote packet
    data_type     = 'B6';
    info_type     = '03';
    market_type   = '4';

    # issue_code    = any{12} >{ issue_code = p; };
    issue_code    = 'KR' issue_code1 %{ issue_code1 = scratch; } 'F' issue_code2 %{ issue_code2 = scratch; };
    issue_seq_no  = any{3};
    market_status = any{2};
    total_bid_vol = quantity %{ total_bid_vol = scratch; };
    total_ask_vol = quantity %{ total_ask_vol = scratch; };

    # load directly into the STG stack, llvm spills otherwise. hence the mess.
    bid1          = price %{ Sp_Arg[-10] = scratch; } quantity %{ Sp_Arg[-9] = scratch; };
    bid2          = price %{ Sp_Arg[ -8] = scratch; } quantity %{ Sp_Arg[-7] = scratch; };
    bid3          = price %{ Sp_Arg[ -6] = scratch; } quantity %{ Sp_Arg[-5] = scratch; };
    bid4          = price %{ Sp_Arg[ -4] = scratch; } quantity %{ Sp_Arg[-3] = scratch; };
    bid5          = price %{ Sp_Arg[ -2] = scratch; } quantity %{ Sp_Arg[-1] = scratch; };
    bids          = bid1 bid2 bid3 bid4 bid5;

    ask1          = price %{ Sp_Arg[-12] = scratch; } quantity %{ Sp_Arg[-11] = scratch; };
    ask2          = price %{ Sp_Arg[-14] = scratch; } quantity %{ Sp_Arg[-13] = scratch; };
    ask3          = price %{ Sp_Arg[-16] = scratch; } quantity %{ Sp_Arg[-15] = scratch; };
    ask4          = price %{ Sp_Arg[-18] = scratch; } quantity %{ Sp_Arg[-17] = scratch; };
    ask5          = price %{ Sp_Arg[-20] = scratch; } quantity %{ Sp_Arg[-19] = scratch; };
    asks          = ask1 ask2 ask3 ask4 ask5;

    ignore        = any{50};

    hour1         = any >{ quote_time = fc - '0'; };
    hour2         = any >{ quote_time *= 10; quote_time += fc - '0'; };
    minute1       = any >{ quote_time *= 60; quote_time += fc - '0'; };
    minute2       = any >{ quote_time *= 10; quote_time += fc - '0'; };
    second1       = any >{ quote_time *= 60; quote_time += fc - '0'; };
    second2       = any >{ quote_time *= 10; quote_time += fc - '0'; };
    usec1         = any >{ quote_time *= 10; quote_time += fc - '0'; };
    usec2         = any >{ quote_time *= 10; quote_time += fc - '0'; };
    quote_time    = hour1 hour2 minute1 minute2 second1 second2 usec1 usec2;
    eom           = 0xFF;

    # account for the IP and UDP header space, should also verify the UDP port
    header        = any{42};

    quote = header data_type info_type market_type issue_code issue_seq_no market_status total_bid_vol bids total_ask_vol asks ignore quote_time eom;

    main := quote;
}%%

typedef void (*HsCall)(int64_t*, int64_t*, int64_t*, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, float, float, float, float, double, double);

void
QuoteParser_run(
    int64_t* restrict Base_Arg,
    int64_t* restrict Sp_Arg,
    int64_t* restrict Hp_Arg,
    const uint8_t* restrict buffer, // R1
    int64_t length, // R2
    int64_t R3_Arg,
    int64_t R4_Arg,
    int64_t R5_Arg,
    int64_t R6_Arg,
    int64_t SpLim_Arg,
    float F1_Arg,
    float F2_Arg,
    float F3_Arg,
    float F4_Arg,
    double D1_Arg,
    double D2_Arg)
{
    int cs;
    %% write init;

    // create undefined variables
    const int64_t iUndef;
    const float fUndef;
    const double dUndef;

    const uint8_t* restrict p = buffer;
    const uint8_t* restrict pe = &buffer[length];

    // XXX: need to check stack
    HsCall fun = (HsCall)Sp_Arg[0];
    int64_t* updated_stack = &Sp_Arg[-20];

    if (__builtin_expect(length != 257, 0)) // including ip/udp headers
    {
        return fun(Base_Arg, updated_stack, Hp_Arg, -3, iUndef, iUndef, iUndef, iUndef, iUndef, SpLim_Arg, fUndef, fUndef, fUndef, fUndef, dUndef, dUndef);
    }

    uint64_t issue_code1;
    uint64_t issue_code2;
    uint64_t quote_time;

    uint64_t total_bid_vol;
    uint64_t total_ask_vol;

    // shared storage space for integer parsing
    uint64_t scratch;

    %% write exec;

    if (__builtin_expect(cs == Kospi_first_final, 1))
    {
        return fun(
            Base_Arg,
            updated_stack,
            Hp_Arg,
            0,
            quote_time,
            issue_code1,
            issue_code2,
            total_bid_vol, // wasted registers... should move some quotes off the stack
            total_ask_vol,
            SpLim_Arg,
            fUndef,
            fUndef,
            fUndef,
            fUndef,
            dUndef,
            dUndef);
    }
    else if (__builtin_expect(cs == Kospi_error, 1))
    {
        return fun(Base_Arg, updated_stack, Hp_Arg, -1, iUndef, iUndef, iUndef, iUndef, iUndef, SpLim_Arg, fUndef, fUndef, fUndef, fUndef, dUndef, dUndef);
    }
    else
    {
        return fun(Base_Arg, updated_stack, Hp_Arg, -2, iUndef, iUndef, iUndef, iUndef, iUndef, SpLim_Arg, fUndef, fUndef, fUndef, fUndef, dUndef, dUndef);
    }
}

