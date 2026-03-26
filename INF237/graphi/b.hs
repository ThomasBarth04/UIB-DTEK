-- import Debug.Trace (traceShow)

traceShow _ = id

main :: IO ()
main = do
    getLine
    xs <- getLine
    print (solve [0] xs)

solve :: [Int] -> String -> Int
solve completed [] = choose (last completed) 2
solve completed ('(':xs) = traceShow ("new layer",xs) solve (0:completed) xs
solve [c] (')':xs) = traceShow ("too many )'s", c, xs)  choose c 2 + solve [0] xs
solve (c:c2:completed) (')':xs) = traceShow ("completed",c,c2,completed,xs)  1 + choose c 2 + solve (c2+1:completed) xs


choose 0 _ = 0
choose n 1 = n
choose n k
    | k == n    = 1
    | k > n     = 0
    | k > n - k = choose n  (n - k)
    | otherwise = ((choose n (k - 1)) * (n - k + 1)) `div` k

