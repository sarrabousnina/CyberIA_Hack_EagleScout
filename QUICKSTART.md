# 🚀 Quick Start Guide

Get EagleScout running in 5 minutes!

## Step 1: Install Dependencies (2 min)

### Option A: Automated (Windows)

```bash
setup.bat
```

### Option B: Manual

```bash
# Install Python packages
pip install -r requirements.txt

# Install Ollama (if not installed)
# Download from https://ollama.com

# Pull the security model
ollama pull foundation-sec-8b-reasoning
```

## Step 2: Configure API Keys (2 min)

1. Copy `.env.example` to `.env`
2. Get free API keys:
   - **NVD**: [nvd.nist.gov/developers](https://nvd.nist.gov/developers/) (free)
   - **OTX**: [otx.alienvault.com](https://otx.alienvault.com/) (free)
   - **Groq**: [console.groq.com](https://console.groq.com/) (free)

3. Add keys to `.env`:

```env
NVD_API_KEY=your_key_here
OTX_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
```

## Step 3: Start Ollama (30 sec)

```bash
# In a separate terminal, start Ollama
ollama serve
```

## Step 4: Run EagleScout! (30 sec)

```bash
streamlit run main.py
```

The dashboard will open in your browser at `http://localhost:8501`

## Step 5: Analyze Infrastructure

1. Click "Browse files" and upload `sample_infrastructure_banking.json`
2. Click "🔍 Run Analysis"
3. Explore:
   - 📊 Risk table with sortable vulnerabilities
   - 🕸️ Interactive attack graph
   - 📈 Risk analytics and charts
   - 🤖 AI security assistant

## What's Happening?

1. **Cloud Agent**: Fetches latest CVEs from NVD + enriches with OTX threat intel
2. **Hybrid Filter**: Uses BM25 + semantic matching to find relevant CVEs
3. **Local LLM**: foundation-sec-8b reasons about risk in your specific infrastructure
4. **Graph Engine**: Maps attack paths from exposed to critical assets
5. **Compliance**: Tags vulnerabilities by sector (PCI-DSS, HIPAA, NIS2, etc.)

## Sample Files

- `sample_infrastructure_banking.json` - Banking sector demo
- `sample_infrastructure_healthcare.json` - Healthcare demo
- `sample_infrastructure_telecom.json` - Telecom demo

## Troubleshooting

### "Model not found"
```bash
ollama pull foundation-sec-8b-reasoning
```

### "Port already in use"
```bash
streamlit run main.py --server.port 8502
```

### "API key error"
- Check `.env` file has all three keys
- Keys should be on separate lines
- No quotes around keys

### Ollama connection error
- Make sure `ollama serve` is running in a separate terminal
- Check Ollama is installed: `ollama --version`

## Next Steps

- Create your own infrastructure JSON (see format in README)
- Try different sectors to see compliance tags change
- Chat with the AI assistant about specific CVEs
- Export results to CSV/JSON for reporting

## Hackathon Demo Flow

1. **Show the problem**: Upload infrastructure JSON
2. **Run the pipeline**: Click "Run Analysis"
3. **Explain the innovation**:
   - "User data stays local"
   - "We trace attack paths, not just list CVEs"
   - "Security-native LLM, not general model"
4. **Show the output**:
   - Attack graph with clickable nodes
   - Risk table sorted by context-aware score
   - Compliance flags for regulated industries
5. **Chat demo**: Ask AI about specific vulnerabilities

---

**Need help?** Check [README.md](README.md) for full documentation.
