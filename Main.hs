{-# LANGUAGE GHCForeignImportPrim #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples  #-}
{-# LANGUAGE UnliftedFFITypes #-}

module Main (main) where

import Control.Applicative
import Control.Concurrent (forkFinally)
import Control.Concurrent.STM
import Control.Monad
import Data.List (sortBy)
import Data.Monoid ((<>))
import Data.Ord (comparing)
import Data.Word (Word32)
import Foreign.ForeignPtr (withForeignPtr)
import GHC.Prim
import GHC.Ptr (Ptr(..))
import GHC.Types
import GHC.Word
import Network.Pcap (PktHdr(..), dispatch, openOffline)
import System.Environment (getArgs)
import Text.Printf

main :: IO ()
main = do
  args <- getArgs
  case args of
    ["-s", fileName] -> do
      -- Charlie would like the results sorted, oblige him

      packetQ <- newTQueueIO            -- ^ STM Queue used for sorting
      lowWater <- newTVarIO 0           -- ^ Low-water mark timestamp
      dispatcherFini <- newEmptyTMVarIO -- ^ Signals pcap dispatcher completion
      writerFini <- newEmptyTMVarIO     -- ^ Signals sorter/writer completion

      -- The dispatcher (pcap callback) needs to raise the low-water mark
      -- so the writer thread will pick up older packets
      let dispatcherThread packet =
            atomically $ do
              writeTQueue packetQ packet
              raiseWatermark lowWater packet

          putOn tmv _ = atomically $ putTMVar tmv ()

      -- spin up the worker threads
      forkFinally (dispatcher fileName dispatcherThread) (putOn dispatcherFini)
      forkFinally (writer dispatcherFini lowWater packetQ) (putOn writerFini)

      -- and wait for them to complete
      _ <- atomically $ takeTMVar writerFini
      return ()

    [fileName] ->
      -- No sorting required, dump packets directly to stdout
      dispatcher fileName printQuotePacket

    _ -> putStrLn "Usage: [-s] FILE"

foreign import prim "QuoteParser_run"
  parseQuote# :: Addr# -> Word# -> (# Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int#, Int# #)

data QuotePacket = QuotePacket
  { quotePacketSec  :: {-# UNPACK #-} !Word32
  , quotePacketUSec :: {-# UNPACK #-} !Word32
  , quoteAcceptTime :: {-# UNPACK #-} !Int
  , quoteIssueHi    :: {-# UNPACK #-} !Int
  , quoteissueLo    :: {-# UNPACK #-} !Int
  , quoteBid5q      :: {-# UNPACK #-} !Int
  , quoteBid5p      :: {-# UNPACK #-} !Int
  , quoteBid4q      :: {-# UNPACK #-} !Int
  , quoteBid4p      :: {-# UNPACK #-} !Int
  , quoteBid3q      :: {-# UNPACK #-} !Int
  , quoteBid3p      :: {-# UNPACK #-} !Int
  , quoteBid2q      :: {-# UNPACK #-} !Int
  , quoteBid2p      :: {-# UNPACK #-} !Int
  , quoteBid1q      :: {-# UNPACK #-} !Int
  , quoteBid1p      :: {-# UNPACK #-} !Int
  , quoteAsk1q      :: {-# UNPACK #-} !Int
  , quoteAsk1p      :: {-# UNPACK #-} !Int
  , quoteAsk2q      :: {-# UNPACK #-} !Int
  , quoteAsk2p      :: {-# UNPACK #-} !Int
  , quoteAsk3q      :: {-# UNPACK #-} !Int
  , quoteAsk3p      :: {-# UNPACK #-} !Int
  , quoteAsk4q      :: {-# UNPACK #-} !Int
  , quoteAsk4p      :: {-# UNPACK #-} !Int
  , quoteAsk5q      :: {-# UNPACK #-} !Int
  , quoteAsk5p      :: {-# UNPACK #-} !Int }

dispatcher :: FilePath -> (QuotePacket -> IO ()) -> IO ()
dispatcher fileName handler = do
  pcap <- openOffline fileName
  _ <- dispatch pcap (-1) $ \ header@PktHdr{hdrCaptureLength = W32# len, hdrSeconds, hdrUseconds} (Ptr addr) ->
    case parseQuote# addr len of
      -- 0 is the success case
      (# 0#, time, issueHi, issueLo, _, _, b5q, b5p, b4q, b4p, b3q, b3p, b2q, b2p, b1q, b1p, a1q, a1p, a2q, a2p, a3q, a3p, a4q, a4p, a5q, a5p #) -> do
         handler $! QuotePacket
           { quotePacketSec  = hdrSeconds
           , quotePacketUSec = hdrUseconds
           , quoteAcceptTime = I# time
           , quoteIssueHi    = I# issueHi
           , quoteissueLo    = I# issueLo
           , quoteBid5q      = I# b5q
           , quoteBid5p      = I# b5p
           , quoteBid4q      = I# b4q
           , quoteBid4p      = I# b4p
           , quoteBid3q      = I# b3q
           , quoteBid3p      = I# b3p
           , quoteBid2q      = I# b2q
           , quoteBid2p      = I# b2p
           , quoteBid1q      = I# b1q
           , quoteBid1p      = I# b1p
           , quoteAsk1q      = I# a1q
           , quoteAsk1p      = I# a1p
           , quoteAsk2q      = I# a2q
           , quoteAsk2p      = I# a2p
           , quoteAsk3q      = I# a3q
           , quoteAsk3p      = I# a3p
           , quoteAsk4q      = I# a4q
           , quoteAsk4p      = I# a4p
           , quoteAsk5q      = I# a5q
           , quoteAsk5p      = I# a5p
           }

      -- otherwise it's a failure and all the other args are undefined
      (# status, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ #) -> return () -- print (I# status)

  return ()

sortQuotes :: [QuotePacket] -> [QuotePacket]
sortQuotes = sortBy $
     comparing quoteAcceptTime
  <> comparing quotePacketSec
  <> comparing quotePacketUSec

-- | Read packets off of the queue that are below the low water mark
getWhile :: Int -> TQueue QuotePacket -> STM [QuotePacket]
getWhile lowWater packetQ = sortQuotes <$> go [] where
  -- bump up the low water mark by 3 seconds
  -- because I'm lazy I will not be comparing against the
  -- receive timestamp. This will cause the results to not
  -- be sorted globally, and so it's not 100% accurate.
  lowWater' = lowWater - 300
  go xs = do
    mx <- tryReadTQueue packetQ
    case mx of
      Just x
        | quoteAcceptTime x <= lowWater' -> go (x:xs)
        | otherwise -> do
            unGetTQueue packetQ x
            if null xs
              then retry
              else return xs

      Nothing
        | null xs   -> retry
        | otherwise -> return xs

-- | Turn the packet queue into a sorted list
getAll :: TQueue QuotePacket -> STM [QuotePacket]
getAll packetQ = sortQuotes <$> go [] where
  go xs = do
    mx <- tryReadTQueue packetQ
    case mx of
      Just x  -> go (x:xs)
      Nothing -> return xs

raiseWatermark :: TVar Int -> QuotePacket -> STM ()
raiseWatermark tv x = do
  v <- readTVar tv
  let x' = quoteAcceptTime x
  -- minimize TVar writes to avoid scheduling the writer
  -- thread when the value hasn't changed
  when (x' > v) $ writeTVar tv x'

writer :: TMVar () -> TVar Int -> TQueue QuotePacket -> IO ()
writer shutdown lowWater packetQ = do
  let getNext = do
        mark <- readTVar lowWater
        getWhile mark packetQ

  -- get the next round of packets to process, if there are any
  mpackets <- atomically $ Right <$> getNext <|>
     -- otherwise getNext will retry and we check to see if this thread should exit
     takeTMVar shutdown *> (Left <$> getAll packetQ)

  case mpackets of
    Right packets -> do
      mapM_ printQuotePacket packets
      writer shutdown lowWater packetQ

    Left packets ->
      mapM_ printQuotePacket packets

printQuotePacket :: QuotePacket -> IO ()
printQuotePacket QuotePacket{..} = do
  putStr $ show quotePacketSec ++ "." ++ show quotePacketUSec ++ " " ++ show quoteAcceptTime ++ " KR" ++ show quoteIssueHi ++ "F" ++ show quoteissueLo ++ " "
  putStr $ concat $ zipWith (\ x y -> show x ++ [y]) [quoteBid5q, quoteBid5p, quoteBid4q, quoteBid4p, quoteBid3q, quoteBid3p, quoteBid2q, quoteBid2p, quoteBid1q, quoteAsk1p] (cycle "@ ")
  putStrLn $ concat $ zipWith (\ x y -> show x ++ [y]) [quoteAsk1q, quoteAsk1p, quoteAsk2q, quoteAsk2p, quoteAsk3q, quoteAsk3p, quoteAsk4q, quoteAsk4p, quoteAsk5q, quoteAsk5p] (cycle "@ ")
