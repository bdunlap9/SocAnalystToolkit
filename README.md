# SOC Analyst Toolkit

SOC Analyst Toolkit is a powerful set of tools designed to assist security analysts with various tasks including log analysis, URL sanitization, decoding, DNS lookup, hashing, and more. The toolkit integrates with Elasticsearch and supports working with various types of hashes, encoded strings, and file formats.

## Features

- Elasticsearch integration for log analysis
- URL sanitization
- Decoding tools for ProofPoint, URL, and Office Safelinks
- URL unshortening
- Base64 decoding
- Cisco Password 7 decoding
- URL unfurling
- Reputation checking for IPs, URLs, and email addresses
- DNS lookups (forward and reverse) and WhoIs lookups
- Hashing functions for files and text input
- Malicious activity checking based on hashes
- Email analysis and templating
- Phishtank URL analysis
- HaveIBeenPwned lookup for email addresses

## Requirements

- Python 3.x
- `pandas`
- `requests`
- `elasticsearch`
- `urllib`

## Installation

1. Clone this repository:
```
git clone https://github.com/your_username/soc_analyst_toolkit.git
```

2. Install the required packages using `pip`:
```
pip install -r requirements.txt
```

## Usage

You can use this toolkit as a standalone Python script or import it as a module in your own projects. Here are some examples of how to use the toolkit:

- To sanitize a URL:
```
python soc_analyst_toolkit.py sanitize http://example.com
```

- To decode a ProofPoint encoded URL:
```
python soc_analyst_toolkit.py decoders proofpoint https%3A%2F%2Fwww.example.com
```

- To perform a reverse DNS lookup:
```
python soc_analyst_toolkit.py dns reverse 8.8.8.8
```

- To hash a file and check for known malicious activity:
```
python soc_analyst_toolkit.py hashing file /path/to/your/file
```

For more detailed usage instructions, run the script with the `-h` or `--help` flag:
```
python soc_analyst_toolkit.py --help
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
