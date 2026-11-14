-- | Email authentication (SPF, DMARC, DKIM) linter. Pure Haskell, base and containers only.
module MailAuth
  ( Rec (..), Sev (..), Finding (..), parseZone, audit, domains, score, grade
  , spfLookups, renderText, renderHtml, estimateKeyBits
  ) where

import Data.Char (isSpace, toLower, isAlphaNum)
import Data.List (isPrefixOf, isSuffixOf, nub, sortOn, stripPrefix)
import Data.Maybe (mapMaybe)

data Rec = Rec { rName :: String, rType :: String, rVal :: String } deriving (Show, Eq)

data Sev = Critical | High | Medium deriving (Show, Eq, Ord, Enum)

data Finding = Finding { fDomain :: String, fRule :: String, fSev :: Sev, fMsg :: String } deriving (Show, Eq)

lower :: String -> String
lower = map toLower

trim :: String -> String
trim = f . f where f = reverse . dropWhile isSpace

-- | Parses lines like: name [ttl] [IN] TYPE value   (quoted TXT chunks are joined).
parseZone :: String -> [Rec]
parseZone = mapMaybe parseLine . lines
  where
    parseLine l0 =
      let l = trim l0
      in if null l || head l `elem` "#;" then Nothing else go (words l)
    go (n : rest) =
      case dropWhile (not . isType) rest of
        (t : v) | length (takeWhile (not . isType) rest) <= 2 -> Just (Rec (norm n) (map toUpperAscii t) (value t (unwords' v)))
        _ -> Nothing
    go [] = Nothing
    isType w = lower w `elem` ["txt", "mx"]
    unwords' = foldr1' (\a b -> a ++ " " ++ b)
    foldr1' _ [] = ""
    foldr1' f xs = foldr1 f xs
    value t v = if lower t == "txt" then joinQuoted v else trim v
    norm = lower . stripDot
    stripDot s = if "." `isSuffixOf` s then init s else s
    toUpperAscii c = if c >= 'a' && c <= 'z' then toEnum (fromEnum c - 32) else c

joinQuoted :: String -> String
joinQuoted s = case dropWhile (/= '"') s of
  [] -> trim s
  (_ : r) -> let (chunk, rest) = break (== '"') r in chunk ++ joinQuoted (drop 1 rest)

txtAt :: [Rec] -> String -> [String]
txtAt rs n = [rVal r | r <- rs, rType r == "TXT", rName r == n]

-- | The mail domains in a zone: anything with MX or SPF, plus bases of _dmarc and _domainkey names.
domains :: [Rec] -> [String]
domains rs = nub (sortOn id (mapMaybe base rs))
  where
    base r
      | Just d <- stripPrefix "_dmarc." (rName r) = Just d
      | Just d <- afterDomainkey (rName r) = Just d
      | rType r == "MX" = Just (rName r)
      | rType r == "TXT" && "v=spf1" `isPrefixOf` lower (rVal r) = Just (rName r)
      | otherwise = Nothing
    afterDomainkey n = case breakOn "._domainkey." n of
      Just (_, d) -> Just d
      Nothing -> Nothing

breakOn :: String -> String -> Maybe (String, String)
breakOn pat = go []
  where
    go acc s | pat `isPrefixOf` s = Just (reverse acc, drop (length pat) s)
    go _ [] = Nothing
    go acc (c : cs) = go (c : acc) cs

-- | DNS-querying mechanisms in an SPF record: the limit is 10.
spfLookups :: String -> Int
spfLookups rec' = length (filter counts (tail' (words (lower rec'))))
  where
    tail' = drop 1
    counts t0 = let t = dropWhile (`elem` "+-~?") t0 in
      any (`isPrefixOf` t) ["include:", "redirect=", "exists:", "mx", "ptr"] || t == "a" || "a:" `isPrefixOf` t || "a/" `isPrefixOf` t

spfAll :: String -> Maybe Char
spfAll rec' = case filter (\t -> dropWhile (`elem` "+-~?") t == "all") (words (lower rec')) of
  [] -> Nothing
  ts -> let t = last ts in Just (if head t `elem` "+-~?" then head t else '+')

tags :: String -> [(String, String)]
tags s = [ (lower (trim k), trim (drop 1 v)) | part <- splitOn ';' s, let (k, v) = break (== '=') part, not (null (trim k)) ]

splitOn :: Char -> String -> [String]
splitOn c s = case break (== c) s of
  (a, []) -> [a]
  (a, _ : r) -> a : splitOn c r

-- | Rough RSA modulus size from the base64 length of the public key (SubjectPublicKeyInfo).
estimateKeyBits :: String -> Int
estimateKeyBits p
  | n < 100 = 512
  | n < 240 = 1024
  | n < 420 = 2048
  | otherwise = 4096
  where n = length (filter isAlphaNum p)

audit :: [Rec] -> [Finding]
audit rs = sortOn (\f -> (fDomain f, fromEnum (fSev f), fRule f)) (concatMap one (domains rs))
  where
    one d = spf d ++ dmarc d ++ dkim d

    spf d =
      let recs = [v | v <- txtAt rs d, "v=spf1" `isPrefixOf` lower v]
          f = Finding d
      in case recs of
        [] -> [f "MA001" High "no SPF record: anyone can spoof this domain and receivers have nothing to check"]
        (_ : _ : _) -> [f "MA002" Critical "more than one SPF record: this is a permanent error and SPF stops working"]
        [r] ->
          concat
            [ case spfAll r of
                Just '+' -> [f "MA003" Critical "SPF ends with +all: it authorises the whole internet"]
                Just '?' -> [f "MA003" High "SPF ends with ?all (neutral): it blocks nothing"]
                Just '~' -> [f "MA003" Medium "SPF ends with ~all (softfail): move to -all once the sources are known"]
                Just _ -> []
                Nothing -> [f "MA003" Medium "SPF has no all mechanism: unlisted senders are not rejected"]
            , [f "MA004" High ("SPF needs " ++ show (spfLookups r) ++ " DNS lookups before nested includes: the limit is 10, over it SPF fails permanently") | spfLookups r > 10]
            , [f "MA004" Medium "SPF uses ptr: deprecated, slow and unreliable" | any ((== "ptr") . dropWhile (`elem` "+-~?")) (words (lower r)) || " ptr:" `isInfix` lower r]
            ]
    isInfix pat s = case breakOn pat s of Just _ -> True; Nothing -> False
    dmarc d =
      let all' = txtAt rs ("_dmarc." ++ d)
          good = [v | v <- all', "v=dmarc1" `isPrefixOf` lower (filter (not . isSpace) (take 12 v)) || "v=dmarc1" `isPrefixOf` lower v]
          f = Finding d
      in case (all', good) of
        ([], _) -> [f "MA005" High "no DMARC record: receivers cannot be told to reject spoofed mail"]
        (_, []) -> [f "MA008" High "a _dmarc TXT record exists but it does not start with v=DMARC1: it is ignored"]
        (_, [v]) ->
          let t = tags v
              p = maybe "" lower (lookup "p" t)
          in concat
               [ case p of
                   "none" -> [f "MA006" Medium "DMARC policy is p=none: monitoring only, spoofed mail is still delivered"]
                   "quarantine" -> []
                   "reject" -> []
                   _ -> [f "MA008" High "DMARC has no valid p= policy: the record is invalid"]
               , [f "MA006" Medium "DMARC has no rua= address: you will never see who is sending as you" | lookup "rua" t == Nothing]
               , [f "MA006" Medium ("DMARC applies to only " ++ pct ++ "% of mail (pct=)") | Just pct <- [lookup "pct" t], pct /= "100"]
               ]
        (_, _ : _ : _) -> [f "MA002" Critical "more than one DMARC record: DMARC is ignored"]
    dkim d =
      concat
        [ let t = tags v; f = Finding d; p = maybe "" id (lookup "p" t); bits = estimateKeyBits p
          in concat
               [ [f "MA007" Critical (sel ++ ": DKIM key looks like " ++ show bits ++ "-bit RSA and can be factored") | not (null p), bits < 1024]
               , [f "MA007" Medium (sel ++ ": DKIM key looks like 1024-bit RSA: rotate to 2048-bit") | not (null p), bits == 1024]
               , [f "MA007" Medium (sel ++ ": DKIM is in testing mode (t=y): receivers ignore failures") | lookup "t" t == Just "y"]
               ]
        | r <- rs, rType r == "TXT"
        , Just (sel, dom) <- [breakOn "._domainkey." (rName r)], dom == d
        , let v = rVal r
        ]

score :: [Finding] -> Int
score fs = max 0 (100 - sum (map pen fs))
  where pen f = case fSev f of Critical -> 30; High -> 15; Medium -> 5

grade :: Int -> Char
grade s | s >= 90 = 'A' | s >= 75 = 'B' | s >= 60 = 'C' | s >= 40 = 'D' | otherwise = 'F'

renderText :: [Rec] -> String
renderText rs = unlines (concatMap block (domains rs))
  where
    fs = audit rs
    block d =
      let mine = filter ((== d) . fDomain) fs
          s = score mine
      in (d ++ ": grade " ++ [grade s] ++ ", score " ++ show s ++ "/100, " ++ show (length mine) ++ " findings")
           : concat [ ["  " ++ pad 9 (map toUpper' (show (fSev f))) ++ fRule f ++ "  " ++ fMsg f] | f <- mine ]
    pad n s = s ++ replicate (n - length s) ' '
    toUpper' c = if c >= 'a' && c <= 'z' then toEnum (fromEnum c - 32) else c

esc :: String -> String
esc = concatMap e where
  e '&' = "&amp;"; e '<' = "&lt;"; e '>' = "&gt;"; e '"' = "&quot;"; e c = [c]

renderHtml :: [Rec] -> String
renderHtml rs = concat
  [ "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>mail-auth-lint</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}h2{margin:26px 0 4px;font-size:17px}.sub{color:#8b98a8}.grade{font-size:30px;font-weight:800;margin-right:8px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}.Critical{color:#f85149;font-weight:700}.High{color:#f0883e;font-weight:700}.Medium{color:#e3b341;font-weight:700}</style></head><body><h1>mail-auth-lint</h1><p class=\"sub\">SPF, DMARC and DKIM linter in Haskell, base and containers only. Synthetic DNS data for example.test domains.</p>"
  , concatMap section (domains rs)
  , "<p class=\"sub\">Reads a zone export, it does not query DNS: nested SPF includes are not expanded, and MTA-STS, BIMI and ARC are not checked.</p></body></html>\n"
  ]
  where
    fs = audit rs
    section d =
      let mine = filter ((== d) . fDomain) fs
          s = score mine
          rows = concat [ "<tr><td class=\"" ++ show (fSev f) ++ "\">" ++ show (fSev f) ++ "</td><td>" ++ fRule f ++ "</td><td>" ++ esc (fMsg f) ++ "</td></tr>" | f <- mine ]
      in "<h2><span class=\"grade\">" ++ [grade s] ++ "</span>" ++ esc d ++ " <span class=\"sub\">" ++ show s ++ "/100</span></h2><table><tr><th>Severity</th><th>Rule</th><th>Finding</th></tr>" ++ rows ++ "</table>"
