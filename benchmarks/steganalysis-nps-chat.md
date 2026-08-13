# NPS Chat steganalysis measurement

Date: 2026-08-13<br>
Corpus: NPS Chat 1.0, 10567 posts, 230623 Unicode scalars<br>
Samples: 100 consecutive-post windows of at least 2048 scalars

The raw corpus is not redistributed because its licence limits use to non-commercial, non-profit education and research. The source URL and SHA-256 are in the JSON report.

None of the four carrier alphabets occurred in the 230,623-scalar baseline. The presence column is therefore an exact-codepoint detector with no false positives on this corpus. The heuristic column uses Sayeh's score threshold of 50.

| Carrier | Embedded symbols / visible scalars | Presence detected | Heuristic detected | Mean score | Mean longest run | Mean positional entropy |
|---|---:|---:|---:|---:|---:|---:|
| zero-width | 0.1% | 100/100 (100%) | 0/100 (0%) | 40.0 | 1.00 | 0.444 |
| zero-width | 0.5% | 100/100 (100%) | 100/100 (100%) | 56.3 | 1.00 | 0.772 |
| zero-width | 1.0% | 100/100 (100%) | 100/100 (100%) | 66.0 | 1.00 | 0.885 |
| zero-width-compat | 0.1% | 100/100 (100%) | 0/100 (0%) | 40.0 | 1.00 | 0.447 |
| zero-width-compat | 0.5% | 100/100 (100%) | 100/100 (100%) | 67.2 | 1.00 | 0.791 |
| zero-width-compat | 1.0% | 100/100 (100%) | 100/100 (100%) | 68.1 | 1.00 | 0.882 |
| variation-selectors | 0.1% | 100/100 (100%) | 0/100 (0%) | 40.0 | 1.00 | 0.443 |
| variation-selectors | 0.5% | 100/100 (100%) | 100/100 (100%) | 56.1 | 1.00 | 0.783 |
| variation-selectors | 1.0% | 100/100 (100%) | 100/100 (100%) | 55.2 | 1.00 | 0.871 |
| unicode-tags | 0.1% | 100/100 (100%) | 0/100 (0%) | 40.0 | 1.00 | 0.433 |
| unicode-tags | 0.5% | 100/100 (100%) | 100/100 (100%) | 56.0 | 1.00 | 0.779 |
| unicode-tags | 1.0% | 100/100 (100%) | 100/100 (100%) | 55.1 | 1.00 | 0.881 |

Scattering held the longest contiguous run to one symbol in every tested sample. It did not conceal the use of a known carrier alphabet. These rates measure this implementation against one disclosed corpus and detector; they are not estimates for every adversary or corpus.
