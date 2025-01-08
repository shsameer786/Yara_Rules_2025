![image](https://github.com/user-attachments/assets/98015e95-f695-416c-b77a-d1c8407f4848)

# YARA Rules for Malware Bazaar Daily Samples (2025)

This repository contains YARA rules generated from daily malware samples obtained from [Malware Bazaar](https://datalake.abuse.ch/malware-bazaar/daily/) for the year 2025. These rules are designed to aid in malware detection and classification based on observed patterns and characteristics in malicious files.

**Author:** Sameer P Sheik - Security Consultant

## Table of Contents

- [Introduction](#introduction)
- [Data Source](#data-source)
- [Repository Structure](#repository-structure)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

---

## Introduction

YARA is a powerful tool for identifying and classifying malware. This repository provides YARA rules derived from the daily malware samples released by Malware Bazaar in 2025. The goal is to help researchers, incident responders, and malware analysts efficiently detect threats using community-driven intelligence.

## Data Source

The rules in this repository are based on samples provided by the Malware Bazaar daily feeds. Malware Bazaar is a project by [abuse.ch](https://abuse.ch/) that collects and shares malware samples to aid the cybersecurity community.

The direct link to the daily sample feed: [Malware Bazaar Daily Feeds](https://datalake.abuse.ch/malware-bazaar/daily/).

## Repository Structure

The repository is organized as follows:

```
├── rules/
│   ├── january/
│   ├── february/
│   ├── ...
│   ├── december/
│
├── examples/
│   ├── detected_files/
│   ├── false_positives/
│
├── scripts/
│   ├── yara_testing_script.py
│   ├── sample_downloader.py
│
├── README.md
├── LICENSE
```

- `rules/`: Contains the YARA rules categorized by month.
- `examples/`: Contains examples of detected files and any observed false positives.
- `scripts/`: Useful scripts for testing YARA rules or downloading daily samples.
- `README.md`: Documentation for the repository.
- `LICENSE`: The license governing the usage of this repository.

## Usage

### Prerequisites

1. Install YARA:

   ```bash
   sudo apt-get install yara
   ```

   Or refer to the [official YARA documentation](https://yara.readthedocs.io/en/stable/gettingstarted.html) for installation instructions on other platforms.

2. Clone this repository:

   ```bash
   git clone https://github.com/shsameer786/Yara_Rules_2025.git
   cd Yara_Rules_2025
   ```

### Running YARA Rules

To scan a file or directory with the provided YARA rules:

```bash
yara -r rules/january/*.yar /path/to/scan
```

Replace `january` with the relevant month folder and `/path/to/scan` with the target file or directory.

### Testing the Rules

Use the `scripts/yara_testing_script.py` to automate testing of rules against known malware and clean files:

```bash
python3 scripts/yara_testing_script.py --rules_dir rules/ --samples_dir /path/to/samples
```

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeatureName`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeatureName`).
5. Open a pull request.

When contributing YARA rules, please ensure:

- Rules are well-documented with comments.
- Testing has been performed against clean and malicious samples to avoid false positives.

## License

This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This repository is intended for educational and research purposes only. Use the YARA rules responsibly and in compliance with local laws and regulations. The authors are not responsible for misuse of the information provided.
