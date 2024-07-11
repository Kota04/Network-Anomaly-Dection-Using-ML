from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, average_precision_score

import pandas as pd
import numpy as np
import os
import logging
import time
import matplotlib.pyplot as plt
import csv
from statsmodels.stats.outliers_influence import variance_inflation_factor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

csv_files = [file for file in os.listdir('./attacks/') if file.endswith('.csv')]

def create_folder(folder_name):
    try:
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
    except OSError as e:
        logging.error(f"Error: Failed to create the directory {folder_name}. Exception: {e}")

# Create necessary folders
create_folder('./results/')
folder_name = './results/result_graph_1/'
create_folder(folder_name)

def calculate_vif(X, thresh=5.0):
    """
    Calculate the Variance Inflation Factor (VIF) for each feature and return
    the features with VIF below the threshold.
    """
    variables = X.columns
    dropped = True
    while dropped:
        dropped = False
        vif = pd.DataFrame()
        vif["VIF"] = [variance_inflation_factor(X[variables].values, i) for i in range(len(variables))]
        vif["variable"] = variables
        max_vif = vif["VIF"].max()
        if max_vif > thresh:
            dropped = True
            drop_variable = vif.sort_values("VIF", ascending=False)["variable"].values[0]
            variables = variables.drop(drop_variable)
            logging.info(f"Dropping {drop_variable} with VIF={max_vif}")
    return X[variables]

# The ml attacks need to perform
ml_list = {
    "Naive Bayes": GaussianNB(),
    "QDA": QDA(),
    "Random Forest": RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),
    "ID3": DecisionTreeClassifier(max_depth=5, criterion="entropy"),
    "AdaBoost": AdaBoostClassifier(algorithm='SAMME'),
    "MLP": MLPClassifier(hidden_layer_sizes=(13, 13, 13), max_iter=500),
    "Nearest Neighbors": KNeighborsClassifier(3)
}

features = {
    "PortScan": ['Total Length of Fwd Packets', 'Flow Bytes/s', 'Subflow Fwd Bytes', 'PSH Flag Count', 'Bwd Packets/s', 'Label'],
    "SSH-Patator": ['Init_Win_bytes_backward', 'Bwd Header Length', 'Bwd Packets/s', 'min_seg_size_forward', 'Fwd Packet Length Max', 'Label'],
    "Infiltration": ['Subflow Fwd Bytes', 'Total Length of Fwd Packets', 'Avg Fwd Segment Size', 'Fwd Packet Length Mean', 'Fwd IAT Min', 'Label'],
    "FTP-Patator": ['Average Packet Size', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Packet Length Variance', 'Fwd Packet Length Std', 'Label'],
    "WebAttack": ['Init_Win_bytes_backward', 'Subflow Fwd Bytes', 'min_seg_size_forward', 'Total Length of Fwd Packets', 'Init_Win_bytes_forward', 'Label'],
    "Heartbleed": ['Total Length of Bwd Packets', 'Packet Length Variance', 'Avg Bwd Segment Size', 'Bwd Packet Length Max', 'Fwd Packet Length Max', 'Label'],
    "Bot": ['Bwd Packet Length Mean', 'Avg Bwd Segment Size', 'Init_Win_bytes_forward', 'Bwd IAT Min', 'Fwd Header Length', 'Label'],
    "DoS Slowhttptest": ['Flow Packets/s', 'Flow IAT Mean', 'Fwd Packet Length Min', 'Init_Win_bytes_backward', 'Bwd Packet Length Mean', 'Label'],
    "DoS slowloris": ['Flow IAT Mean', 'Bwd Packet Length Mean', 'Avg Bwd Segment Size', 'min_seg_size_forward', 'SYN Flag Count', 'Label'],
    "DoS Hulk": ['Bwd Packet Length Std', 'Average Packet Size', 'Bwd Packets/s', 'Init_Win_bytes_forward', 'Fwd Packet Length Std', 'Label'],
    "DoS GoldenEye": ['Flow IAT Max', 'min_seg_size_forward', 'Bwd Packet Length Std', 'Flow IAT Min', 'Init_Win_bytes_backward', 'Label'],
    "DDoS": ['Bwd Packet Length Std', 'act_data_pkt_fwd', 'Subflow Bwd Packets', 'Total Backward Packets', 'Fwd IAT Total', 'Label']
}

result_path = './results/result_graph_1/results.csv'
repetition = 10

start_time = time.time()

with open(result_path, "w", newline="", encoding="utf-8") as result_file:
    writer = csv.writer(result_file)
    writer.writerow(["File", "ML algorithm", "Avg Accuracy", "Avg Precision", "Avg Recall", "Avg F1-score", "Avg Time"])

    for j in csv_files:
        logging.info(f"Processing file: {j}")
        print('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % ("File", "ML algorithm", "Avg Accuracy", "Avg Precision", "Avg Recall", "Avg F1-score", "Avg Time"))
        
        feature_list = features[j[:-4]]
        df = pd.read_csv(f'./attacks/{j}', usecols=feature_list)
        df = df.fillna(0)
        
        # Replace infinities and large values with finite values
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        df[numeric_columns] = df[numeric_columns].replace([np.inf, -np.inf], np.nan)
        df.fillna(df[numeric_columns].max().max(), inplace=True)
        
        df["Label"] = df["Label"].apply(lambda x: 1 if x == "BENIGN" else 0)
        y = df["Label"]
        X = df.drop("Label", axis=1)
        
        # Remove collinear features
        X = calculate_vif(X)
        
        for algo_name, algo in ml_list.items():
            logging.info(f"Running {algo_name} on {j}")
            
            precision_scores = []
            recall_scores = []
            f1_scores = []
            accuracy_scores = []
            times = []
            
            for _ in range(repetition):
                split_start_time = time.time()
                
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=repetition)
                
                algo.fit(X_train, y_train)
                predictions = algo.predict(X_test)
                
                accuracy_scores.append(accuracy_score(y_test, predictions))
                precision_scores.append(precision_score(y_test, predictions, average='macro'))
                recall_scores.append(recall_score(y_test, predictions, average='macro'))
                f1_scores.append(f1_score(y_test, predictions, average='macro'))
                times.append(time.time() - split_start_time)
            
            avg_accuracy = np.mean(accuracy_scores)
            avg_precision = np.mean(precision_scores)
            avg_recall = np.mean(recall_scores)
            avg_f1 = np.mean(f1_scores)
            avg_time = np.mean(times)
            
            logging.info(f"Completed {algo_name} on {j} with Avg Accuracy: {avg_accuracy}, Avg Precision: {avg_precision}, Avg Recall: {avg_recall}, Avg F1-score: {avg_f1}, Avg Time: {avg_time}")
            print('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % (
                j[:-4], algo_name, round(avg_accuracy, 2), round(avg_precision, 2),
                round(avg_recall, 2), round(avg_f1, 2),
                round(avg_time, 4)
            ))
            
            writer.writerow([j[:-4], algo_name, avg_accuracy, avg_precision, avg_recall, avg_f1, avg_time])
        
        # Plotting the box plots
        fig, axes = plt.subplots(nrows=2, ncols=4, figsize=(12, 6), sharey=True)
        for idx, algo_name in enumerate(ml_list.keys()):
            row, col = divmod(idx, 4)
            axes[row, col].boxplot(f1_scores)
            axes[row, col].set_title(f"{j[:-4]} - {algo_name}", fontsize=7)
            axes[row, col].set_ylabel("F measure")
        
        plt.savefig(f'{folder_name}/{j[:-4]}.pdf', bbox_inches='tight', format='pdf')

        plt.close()
        
        logging.info(f"Completed processing of {j}")
        print("\n------------------------------------------------------------------------------------------------------\n\n")
    
logging.info(f"Mission accomplished! Total operation time: {time.time() - start_time} seconds")
