

  <h1>🚨 FuzzCollector v2.1</h1>
  <p>A Python-based CLI tool to discover <strong>reflected XSS</strong> and <strong>HTML injection</strong> vulnerabilities by fuzzing subdomains and pulling archived endpoints from the Wayback Machine.</p>

  <hr>

  <h2>📦 Installation</h2>

  <h3>1. Clone the tool</h3>
  <pre><code>git clone https://github.com/yourname/fuzzcollector
cd fuzzcollector</code></pre>

  <h3>2. Install Python dependencies</h3>
  <pre><code>pip install -r requirements.txt</code></pre>

  <h3>3. (Optional) Use setup script</h3>
  <pre><code>chmod +x install.sh
./install.sh</code></pre>

  <hr>

  <h2>🚀 Usage</h2>

  <pre><code>python3 redhet.py target.com</code></pre>

  <p>📌 Example:</p>
  <pre><code>python3 redhet.py testphp.vulnweb.com</code></pre>

  <hr>

  <h2>📝 Wordlist Format (<code>subs.txt</code>)</h2>
  <pre><code>www
admin
api
mail
portal
test
dev</code></pre>

  <hr>

  <h2>📂 Output Files</h2>
  <p>All results are saved in the <code>output/</code> directory:</p>
  <table>
    <thead>
      <tr><th>File</th><th>Description</th></tr>
    </thead>
    <tbody>
      <tr><td>livesubdomains.txt</td><td>Alive subdomains</td></tr>
      <tr><td>endpoints.txt</td><td>URLs pulled from Wayback Machine</td></tr>
      <tr><td>xss_html_results.txt</td><td>Detected XSS and HTML injection URLs</td></tr>
    </tbody>
  </table>

  <hr>

  <h2>💉 Payloads Used</h2>
  <table>
    <thead>
      <tr><th>Type</th><th>Payload</th></tr>
    </thead>
    <tbody>
      <tr><td>XSS</td><td><code>&lt;script&gt;alert(1337)&lt;/script&gt;</code></td></tr>
      <tr><td>HTML</td><td><code>&lt;/a&gt;&lt;a href="https://bing.com"&gt;click&lt;/a&gt;</code></td></tr>
    </tbody>
  </table>
  <p>All payloads are injected into every query parameter of discovered URLs.</p>

  <hr>

  <h2>📌 Requirements</h2>

  <h3>Install required Python libraries:</h3>
  <pre><code>pip install requests==2.31.0 rich==13.7.1 urllib3==2.2.1</code></pre>

  <h3>Ensure curl is available:</h3>
  <pre><code>sudo apt install curl -y</code></pre>

  <hr>

  <h2>⚠️ Legal Disclaimer</h2>
  <p>This tool is intended <strong>only</strong> for educational purposes and authorized security testing. <br>
  Do <strong>NOT</strong> scan or attack any system you do not own or have explicit permission to test.</p>

  <hr>

  <h2>📌 Social Media</h2>
  https://www.instagram.com/whiterose.jpeg

  <h2>👨‍💻 Author</h2>
  <p><strong>whiterose</strong><br>
  Bug Bounty Hunter | Red Teamer | CTF Player</p>

</body>
</html>
