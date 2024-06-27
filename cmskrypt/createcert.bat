makecert.exe ^
-n "CN=CARoot" ^
-r ^
-pe ^
-a sha256 ^
-len 2048 ^
-cy authority ^
-sv CARoot.pvk ^
CARoot.cer

pvk2pfx.exe ^
-pvk CARoot.pvk ^
-spc CARoot.cer ^
-pfx CARoot.pfx

-po Test123