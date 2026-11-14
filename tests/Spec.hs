module Main (main) where

import Control.Monad (unless)
import Data.IORef
import Data.List (isInfixOf)
import MailAuth
import System.Exit

check :: IORef (Int, Int) -> String -> Bool -> IO ()
check ref name ok = do
  modifyIORef ref (\(n, f) -> (n + 1, if ok then f else f + 1))
  unless ok (putStrLn ("FAIL: " ++ name))

rules :: String -> [String]
rules z = map fRule (audit (parseZone z))

good :: String
good = unlines
  [ "a.test. 300 IN MX 10 mx.a.test."
  , "a.test. 300 IN TXT \"v=spf1 include:_spf.x.test -all\""
  , "_dmarc.a.test. 300 IN TXT \"v=DMARC1; p=reject; rua=mailto:r@a.test\""
  ]

main :: IO ()
main = do
  ref <- newIORef (0, 0)
  let c = check ref
  -- parsing
  c "comments and blanks ignored" (parseZone "; c\n# c\n\n" == [])
  c "quoted chunks are joined" (map rVal (parseZone "a.test. IN TXT \"v=spf1 \" \"-all\"") == ["v=spf1 -all"])
  c "names are lower-cased and the trailing dot dropped" (map rName (parseZone "A.Test. 300 IN TXT \"x\"") == ["a.test"])
  c "ttl and class are optional" (length (parseZone "a.test TXT \"x\"\na.test 60 IN TXT \"y\"") == 2)
  c "semicolons inside quotes survive" (map rVal (parseZone "_dmarc.a.test. TXT \"v=DMARC1; p=none\"") == ["v=DMARC1; p=none"])
  c "garbage lines are skipped, not fatal" (parseZone "just some words\n\0\0" == [])
  -- domains
  c "domains found from MX, SPF, DMARC and DKIM names"
    (domains (parseZone "a.test MX 10 m\n_dmarc.b.test TXT \"v=DMARC1; p=none\"\ns._domainkey.c.test TXT \"v=DKIM1; p=x\"\nd.test TXT \"v=spf1 -all\"") == ["a.test", "b.test", "c.test", "d.test"])
  -- clean
  c "a good zone has no findings" (rules good == [])
  c "score and grade of a clean domain" (score [] == 100 && grade 100 == 'A')
  -- SPF
  c "MA001 no SPF" ("MA001" `elem` rules "a.test MX 10 m\n")
  c "MA002 two SPF records" ("MA002" `elem` rules (good ++ "a.test. TXT \"v=spf1 -all\"\n"))
  c "MA003 +all is critical" (any (\f -> fRule f == "MA003" && fSev f == Critical) (audit (parseZone "a.test TXT \"v=spf1 +all\"")))
  c "MA003 ?all is high" (any (\f -> fRule f == "MA003" && fSev f == High) (audit (parseZone "a.test TXT \"v=spf1 mx ?all\"")))
  c "MA003 ~all is medium" (any (\f -> fRule f == "MA003" && fSev f == Medium) (audit (parseZone "a.test TXT \"v=spf1 mx ~all\"")))
  c "bare all with no qualifier means +all" (any (\f -> fRule f == "MA003" && fSev f == Critical) (audit (parseZone "a.test TXT \"v=spf1 all\"")))
  c "-all is fine" (not ("MA003" `elem` rules good))
  c "no all mechanism is reported" ("MA003" `elem` rules "a.test TXT \"v=spf1 mx\"\n")
  c "spf lookups counted" (spfLookups "v=spf1 include:a include:b mx a ip4:1.2.3.4 -all" == 4)
  c "ip4 and all are not lookups" (spfLookups "v=spf1 ip4:1.2.3.4 ip6:::1 -all" == 0)
  c "MA004 over ten lookups" ("MA004" `elem` rules ("a.test TXT \"v=spf1 " ++ concatMap (\i -> "include:i" ++ show (i :: Int) ++ ".test ") [1 .. 11] ++ "-all\"\n"))
  c "MA004 ten lookups is allowed" (not ("MA004" `elem` rules ("a.test TXT \"v=spf1 " ++ concatMap (\i -> "include:i" ++ show (i :: Int) ++ ".test ") [1 .. 10] ++ "-all\"\n")))
  c "MA004 ptr is flagged" ("MA004" `elem` rules "a.test TXT \"v=spf1 ptr -all\"\n")
  -- DMARC
  c "MA005 no DMARC" ("MA005" `elem` rules "a.test TXT \"v=spf1 -all\"\n")
  c "MA006 p=none" ("MA006" `elem` rules "a.test TXT \"v=spf1 -all\"\n_dmarc.a.test TXT \"v=DMARC1; p=none; rua=mailto:r@a.test\"\n")
  c "MA006 missing rua" ("MA006" `elem` rules "a.test TXT \"v=spf1 -all\"\n_dmarc.a.test TXT \"v=DMARC1; p=reject\"\n")
  c "MA006 pct below 100" ("MA006" `elem` rules "a.test TXT \"v=spf1 -all\"\n_dmarc.a.test TXT \"v=DMARC1; p=reject; rua=mailto:r@a.test; pct=50\"\n")
  c "MA008 malformed DMARC" ("MA008" `elem` rules "a.test TXT \"v=spf1 -all\"\n_dmarc.a.test TXT \"p=reject\"\n")
  c "MA008 invalid policy" ("MA008" `elem` rules "a.test TXT \"v=spf1 -all\"\n_dmarc.a.test TXT \"v=DMARC1; p=banana; rua=mailto:r@a.test\"\n")
  c "MA002 duplicate DMARC" ("MA002" `elem` rules (good ++ "_dmarc.a.test. TXT \"v=DMARC1; p=none\"\n"))
  -- DKIM
  c "key size estimates" (estimateKeyBits (replicate 90 'A') == 512 && estimateKeyBits (replicate 216 'A') == 1024 && estimateKeyBits (replicate 392 'A') == 2048)
  c "MA007 1024-bit key" ("MA007" `elem` rules (good ++ "s._domainkey.a.test TXT \"v=DKIM1; k=rsa; p=" ++ replicate 216 'A' ++ "\"\n"))
  c "MA007 2048-bit key is fine" (not ("MA007" `elem` rules (good ++ "s._domainkey.a.test TXT \"v=DKIM1; k=rsa; p=" ++ replicate 392 'A' ++ "\"\n")))
  c "MA007 testing mode" ("MA007" `elem` rules (good ++ "s._domainkey.a.test TXT \"v=DKIM1; t=y; p=" ++ replicate 392 'A' ++ "\"\n"))
  c "MA007 revoked key (empty p=) is not a finding" (not ("MA007" `elem` rules (good ++ "s._domainkey.a.test TXT \"v=DKIM1; p=\"\n")))
  -- scoring
  c "penalties add up and floor at zero" (score [Finding "d" "r" Critical "" | _ <- [1 .. 5 :: Int]] == 0)
  c "grades" (map grade [95, 80, 65, 45, 10] == "ABCDF")
  -- output
  let evil = parseZone "<b>.test TXT \"v=spf1 +all\"\n"
      html = renderHtml evil
  c "html escapes names" (not ("<b>.test" `isInfixOf` html) && "&lt;b&gt;.test" `isInfixOf` html)
  c "html has a strict CSP" ("default-src 'none'" `isInfixOf` html)
  -- robustness
  let junk = [ toEnum (32 + (i * 37 + i * i) `mod` 95) | i <- [1 .. 4000 :: Int] ]
  c "junk input does not crash" (length (renderText (parseZone junk)) >= 0 && length (renderHtml (parseZone junk)) > 0)
  -- sample
  z <- readFile "examples/zone.txt"
  let recs = parseZone z
      byDomain d = [f | f <- audit recs, fDomain f == d]
  c "sample: four domains" (length (domains recs) == 4)
  c "sample: shop is clean" (null (byDomain "shop.example.test"))
  c "sample: legacy is grade F" (grade (score (byDomain "legacy.example.test")) == 'F')
  c "sample: parked has no SPF and no DMARC" (map fRule (byDomain "parked.example.test") == ["MA001", "MA005"])
  c "sample: bulk has over ten lookups" ("MA004" `elem` map fRule (byDomain "bulk.example.test"))
  (n, f) <- readIORef ref
  putStrLn (if f == 0 then "all " ++ show n ++ " passed" else show f ++ " of " ++ show n ++ " failed")
  if f == 0 then exitSuccess else exitFailure
