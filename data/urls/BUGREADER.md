# Bugreader.com — why it is not auto-ingested

The public report directory at [bugreader.com/reports](https://bugreader.com/reports) is **client-side rendered**
(HTML shell + JavaScript). There is **no stable anonymous JSON/sitemap** in the initial document for this pipeline
to harvest permalinks the way we do for static blogs or RSS.

**What you can do instead (authorized + polite):**

1. Use the site in a normal browser and copy report URLs you have rights to use for training
   (respect [Bugreader Terms](https://bugreader.com/terms) and [Privacy](https://bugreader.com/privacy)).
2. Paste them into `bugreader_manual.txt` (copy from `data/urls/bugreader_manual.example.txt`). Lines starting with `#` are skipped.
3. Merge into discovery output or pass directly to ingestion:

   ```bash
   hunter-llm collect-urls data/urls/bugreader_manual.txt --append
   ```

If Bugreader later publishes a public RSS feed, sitemap, or documented read-only API, we can wire it into
`discover-writeup-urls` the same way as Medium feeds.
