{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GHCForeignImportPrim #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE UnboxedTuples  #-}
{-# LANGUAGE UnliftedFFITypes #-}

module Main where

import Foreign.ForeignPtr (withForeignPtr)
import GHC.Prim
import GHC.Ptr (Ptr(..))
import GHC.Types
import GHC.Word
import Network.Pcap (PktHdr(..), dispatch, openOffline)
import Text.Printf

foreign import prim "QuoteParser_run"
  parseQuote# :: Addr# -> Word# -> (# Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int# #)

main :: IO ()
main = do
  pcap <- openOffline "/Users/nhowell/Downloads/mdf-kospi200.20110216-0.pcap"
  _ <- dispatch pcap (-1) $ \ header@PktHdr{hdrCaptureLength = W32# len, hdrSeconds, hdrUseconds} (Ptr addr) -> do
    case parseQuote# addr len of
      -- 0 is the success case
      (# 0#, time, issueHi, issueLo, totalBidVol, totalAskVol, b5q, b5p, b4q, b4p, b3q, b3p, b2q, b2p, b1q, b1p, a1q, a1p, a2q, a2p, a3q, a3p, a4q, a4p, a5q, a5p #) -> do
         putStr $ show hdrSeconds ++ "." ++ show hdrUseconds ++ " " ++ show (I# time) ++ " KR" ++ show (I# issueHi) ++ "F" ++ show (I# issueLo) ++ " "
         putStr $ concat $ zipWith (\ x y -> x ++ [y]) (map show [I# b5q, I# b5p, I# b4q, I# b4p, I# b3q, I# b3p, I# b2q, I# b2p, I# b1q, I# b1p]) (cycle "@ ")
         putStrLn $ concat $ zipWith (\ x y -> x ++ [y]) (map show [I# a1q, I# a1p, I# a2q, I# a2p, I# a3q, I# a3p, I# a4q, I# a4p, I# a5q, I# a5p]) (cycle "@ ")

      -- otherwise it's a failure and all the other args are undefined
      (# status, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ #) -> return () -- print (I# status)

  return ()
