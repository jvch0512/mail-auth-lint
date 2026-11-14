module Main (main) where

import MailAuth
import System.Environment (getArgs)
import System.Exit
import System.IO
import Control.Exception (try, IOException)

usage :: String
usage = "usage: mail-auth-lint <zone.txt> [--html] [--fail-below SCORE]\nExit: 0 ok, 1 a domain scores below --fail-below, 2 bad input.\n"

main :: IO ()
main = do
  args <- getArgs
  case args of
    (path : rest) | take 1 path /= "-" -> run path rest
    _ -> hPutStr stderr usage >> exitWith (ExitFailure 2)

run :: FilePath -> [String] -> IO ()
run path rest = do
  (html, failBelow) <- case parseOpts rest False Nothing of
    Just o -> pure o
    Nothing -> hPutStr stderr usage >> exitWith (ExitFailure 2)
  r <- try (readFile path) :: IO (Either IOException String)
  case r of
    Left e -> hPutStrLn stderr ("error: " ++ show e) >> exitWith (ExitFailure 2)
    Right txt -> do
      let recs = parseZone txt
      putStr (if html then renderHtml recs else renderText recs)
      let fs = audit recs
          worst = minimum (100 : [score [f | f <- fs, fDomain f == d] | d <- domains recs])
      case failBelow of
        Just n | worst < n -> exitWith (ExitFailure 1)
        _ -> pure ()

parseOpts :: [String] -> Bool -> Maybe Int -> Maybe (Bool, Maybe Int)
parseOpts [] h f = Just (h, f)
parseOpts ("--html" : t) _ f = parseOpts t True f
parseOpts ("--fail-below" : n : t) h _ | [(v, "")] <- reads n = parseOpts t h (Just v)
parseOpts _ _ _ = Nothing
