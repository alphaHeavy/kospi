#!/usr/bin/env python

top = '.'
out = 'build'

def configure(ctx):
  ctx.find_program('ragel', var='RAGEL')
  ctx.find_program('clang', var='CLANG')
  ctx.find_program('llc', var='LLC')
  ctx.find_program('ghc', var='GHC')
  ctx.find_program('sed', var='SED')
  ctx.env.FIXUP    = 's/call void/call cc10 void/; s/define void/define cc10 void/;'
  ctx.env.LLCOPT   = '-O3 -pre-RA-sched=list-burr -regalloc=greedy -relocation-model=static'
  ctx.env.CLANGOPT = '-O3'
  ctx.env.GHCOPT   = '-O2 -rtsopts -threaded'

def build(bld):
  bld(rule='${RAGEL} -G2 ${SRC} -o ${TGT}',                          source='Kospi.rl',             target='Kospi.c')
  bld(rule='${CLANG} ${CLANGOPT} -emit-llvm -S -c ${SRC} -o ${TGT}', source='Kospi.c',              target='Kospi.ll')
  bld(rule='${SED} -e "${FIXUP}" < ${SRC} > ${TGT}',                 source='Kospi.ll',             target='Kospi.ll-patched')
  bld(rule='${LLC} ${LLCOPT} -filetype=obj ${SRC} -o ${TGT}',        source='Kospi.ll-patched',     target='Kospi.o')
  bld(rule='${GHC} ${GHCOPT} --make -outputdir=. ${SRC} -o ${TGT}',  source=['Kospi.o', 'Main.hs'], target='tsuru')
