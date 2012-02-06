#!/usr/bin/env python

top = '.'
out = 'build'

def configure(ctx):
  ctx.find_program('ragel', var='RAGEL')
  ctx.find_program('clang', var='CLANG')
  ctx.find_program('llc', var='LLC')
  ctx.find_program('llvm-dis', var='LLVM_DIS')
  ctx.find_program('ghc', var='GHC')
  ctx.find_program('sed', var='SED')
  ctx.env.FIXUP = 's/call void/call cc10 void/; s/define void/define cc10 void/;'

def build(bld):
  bld(rule='${RAGEL} -G2 ${SRC} -o ${TGT}',                                      source='Kospi.rl',             target='Kospi.c')
  bld(rule='${CLANG} -O3 -emit-llvm -c ${SRC} -o ${TGT}',                        source='Kospi.c',              target='Kospi.bc')
  bld(rule='${LLVM_DIS} ${SRC} -o ${TGT}',                                       source='Kospi.bc',             target='Kospi.ll')
  bld(rule='${SED} -e "${FIXUP}" < ${SRC} > ${TGT}',                             source='Kospi.ll',             target='Kospi.ll-patched')
  bld(rule='${LLC} -O3 -relocation-model=static -filetype=obj ${SRC} -o ${TGT}', source='Kospi.ll-patched',     target='Kospi.o')
  bld(rule='${GHC} -O2 --make -rtsopts -outputdir=. ${SRC} -o ${TGT}',           source=['Kospi.o', 'Main.hs'], target='tsuru')

