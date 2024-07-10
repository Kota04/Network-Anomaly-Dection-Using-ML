Certainly! Here’s the modified README content:

## Preprocessing

The preprocessing steps ensure that the CICIDS2017 dataset is clean and ready for analysis. The following steps are performed:

1. **Aligning Columns**: Since all CSV files do not have the same number of columns, we align them by creating a union of all columns and adding missing columns as necessary.
2. **Removing Duplicate Columns**: Duplicate columns are identified and removed to avoid redundancy.
3. **Handling Null Values**: Null values are handled appropriately to ensure the integrity of the dataset.
4. **Joining Different Datasets**: Multiple CSV files are concatenated into a single DataFrame.
5. **Combining Web Attacks**: All types of web attacks are normalized under a single label 'WebAttack' for consistency.

## Statistics

We also generate statistical visualizations to understand the distribution of different attack types in the dataset:

- **Attack Frequency Graph**: A bar plot is generated to show the frequency of different attack types. The attacks are categorized into small, medium, and large based on their occurrence counts.

The generated plots are saved as images for further analysis.

## Attack Filter

The dataset is divided into separate files for each attack type. Each file contains 70% benign samples and 30% attack samples to ensure a balanced distribution for training purposes. The following attack types are included:

- BENIGN
- Bot
- DDoS
- DoS GoldenEye
- DoS Hulk
- DoS Slowhttptest
- DoS slowloris
- FTP-Patator
- Heartbleed
- Infiltration
- PortScan
- SSH-Patator
- WebAttack

This structured division helps in creating specific training sets for each type of attack, facilitating more focused and effective machine learning model training.

### Directory Structure

- `./CSVs/`: Contains the original CSV files.
- `./attacks/`: Contains the generated attack-specific CSV files.
- `./graphs/`: Contains the generated statistical visualizations.

### Usage

1. **Preprocessing**: Run the preprocessing script to clean and prepare the dataset.
2. **Statistics Generation**: Run the script to generate statistical visualizations.
3. **Attack Filter**: Run the script to divide the dataset into attack-specific files with the desired benign-to-attack ratio.

### Notes

- Ensure that all the original CSV files are placed in the `./CSVs/` folder before running the preprocessing script.
- The generated attack-specific CSV files will be saved in the `./attacks/` folder.
- The statistical visualizations will be saved in the `./graphs/` folder.

This README provides a comprehensive overview of the preprocessing and analysis steps, ensuring clarity and ease of use for further dataset analysis and model training.