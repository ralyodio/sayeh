# NPS Chat Corpus

Sayeh's published steganalysis measurements use release 1.0 of the NPS Chat
Corpus. The corpus contains 10,567 privacy-masked chat posts collected in 2006.

The raw corpus is not part of this repository. Its licence permits only
non-commercial, non-profit educational and research use, which is narrower than
Sayeh's open-source licences.

- Archive: <https://raw.githubusercontent.com/nltk/nltk_data/gh-pages/packages/corpora/nps_chat.zip>
- SHA-256: `a4433d5da5e62fdbede49efa572a53a0139fff1014ffbe86cb263e17cbb4a837`
- NLTK corpus documentation: <https://www.nltk.org/howto/corpus.html#instantial-access>

After downloading and extracting the archive, reproduce the aggregate report:

```console
cargo xtask analyse-corpus /path/to/nps_chat
```

The command replaces `benchmarks/steganalysis-nps-chat.json` and its Markdown
rendering. No post text is copied into either report.
