### Hardware

Benchmarked on AWS EC2 `c5.2xlarge`:
```
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8124M CPU @ 3.00GHz
stepping	: 4
cpu MHz		: 3364.758
cache size	: 25344 KB
```

### Measurements

```
Rate limiter            time:   [15.531 ns 15.544 ns 15.556 ns]

Parsing/analyze_raw_request: size 469 bytes
                        time:   [792.69 ns 792.95 ns 793.22 ns]
                        thrpt:  [563.87 MiB/s 564.06 MiB/s 564.25 MiB/s]
Found 8 outliers among 200 measurements (4.00%)
  4 (2.00%) low mild
  2 (1.00%) high mild
  2 (1.00%) high severe
Parsing/analyze_raw_request: size 1405 bytes
                        time:   [2.0777 us 2.0789 us 2.0807 us]
                        thrpt:  [643.98 MiB/s 644.53 MiB/s 644.91 MiB/s]
Found 7 outliers among 200 measurements (3.50%)
  1 (0.50%) low severe
  3 (1.50%) low mild
  2 (1.00%) high mild
  1 (0.50%) high severe
Parsing/analyze_raw_request: size 26925 bytes
                        time:   [30.340 us 30.345 us 30.350 us]
                        thrpt:  [846.05 MiB/s 846.20 MiB/s 846.32 MiB/s]
Found 22 outliers among 200 measurements (11.00%)
  3 (1.50%) low severe
  4 (2.00%) low mild
  5 (2.50%) high mild
  10 (5.00%) high severe

Compliant/analyze_request: size 440 bytes
                        time:   [280.04 ns 280.19 ns 280.36 ns]
                        thrpt:  [1.4616 GiB/s 1.4625 GiB/s 1.4633 GiB/s]
Found 14 outliers among 200 measurements (7.00%)
  2 (1.00%) low mild
  5 (2.50%) high mild
  7 (3.50%) high severe
Compliant/analyze_request: size 1356 bytes
                        time:   [863.01 ns 863.69 ns 864.38 ns]
                        thrpt:  [1.4610 GiB/s 1.4622 GiB/s 1.4633 GiB/s]
Found 5 outliers among 200 measurements (2.50%)
  3 (1.50%) low mild
  1 (0.50%) high mild
  1 (0.50%) high severe
Compliant/analyze_request: size 26716 bytes
                        time:   [12.942 us 12.997 us 13.110 us]
                        thrpt:  [1.8978 GiB/s 1.9145 GiB/s 1.9225 GiB/s]
Found 2 outliers among 200 measurements (1.00%)
  2 (1.00%) high severe

Non-Compliant/analyze_request: size 493 bytes
                        time:   [1.1793 us 1.1794 us 1.1795 us]
                        thrpt:  [398.61 MiB/s 398.65 MiB/s 398.69 MiB/s]
Found 30 outliers among 200 measurements (15.00%)
  5 (2.50%) low severe
  5 (2.50%) low mild
  13 (6.50%) high mild
  7 (3.50%) high severe
Non-Compliant/analyze_request: size 1409 bytes
                        time:   [1.8549 us 1.8550 us 1.8552 us]
                        thrpt:  [724.32 MiB/s 724.37 MiB/s 724.41 MiB/s]
Found 16 outliers among 200 measurements (8.00%)
  3 (1.50%) low severe
  3 (1.50%) low mild
  7 (3.50%) high mild
  3 (1.50%) high severe
Non-Compliant/analyze_request: size 26769 bytes
                        time:   [14.635 us 14.648 us 14.675 us]
                        thrpt:  [1.6989 GiB/s 1.7019 GiB/s 1.7034 GiB/s]
Found 27 outliers among 200 measurements (13.50%)
  5 (2.50%) low severe
  11 (5.50%) high mild
  11 (5.50%) high severe

Malicious/analyze_request: size 493 bytes
                        time:   [2.4829 us 2.4830 us 2.4831 us]
                        thrpt:  [189.35 MiB/s 189.35 MiB/s 189.36 MiB/s]
Found 21 outliers among 200 measurements (10.50%)
  7 (3.50%) low severe
  4 (2.00%) low mild
  3 (1.50%) high mild
  7 (3.50%) high severe

Malicious/analyze_request: size 1409 bytes
                        time:   [3.4769 us 3.4772 us 3.4776 us]
                        thrpt:  [386.39 MiB/s 386.44 MiB/s 386.48 MiB/s]
Found 20 outliers among 200 measurements (10.00%)
  6 (3.00%) low severe
  3 (1.50%) low mild
  7 (3.50%) high mild
  4 (2.00%) high severe

Malicious/analyze_request: size 26769 bytes
                        time:   [26.885 us 26.886 us 26.887 us]
                        thrpt:  [949.50 MiB/s 949.53 MiB/s 949.56 MiB/s]
Found 22 outliers among 200 measurements (11.00%)
  4 (2.00%) low severe
  5 (2.50%) low mild
  7 (3.50%) high mild
  6 (3.00%) high severe

Compliant with logging/analyze_request: size 440 bytes
                        time:   [305.23 ns 305.28 ns 305.34 ns]
                        thrpt:  [1.3420 GiB/s 1.3423 GiB/s 1.3425 GiB/s]
Found 19 outliers among 200 measurements (9.50%)
  5 (2.50%) low mild
  9 (4.50%) high mild
  5 (2.50%) high severe

Compliant with logging/analyze_request: size 1356 bytes
                        time:   [885.34 ns 885.89 ns 886.46 ns]
                        thrpt:  [1.4246 GiB/s 1.4255 GiB/s 1.4264 GiB/s]
Found 14 outliers among 200 measurements (7.00%)
  5 (2.50%) low mild
  8 (4.00%) high mild
  1 (0.50%) high severe

Compliant with logging/analyze_request: size 26716 bytes
                        time:   [12.977 us 12.982 us 12.991 us]
                        thrpt:  [1.9153 GiB/s 1.9165 GiB/s 1.9174 GiB/s]
Found 9 outliers among 200 measurements (4.50%)
  2 (1.00%) low mild
  3 (1.50%) high mild
  4 (2.00%) high severe
```