# MQTTEEB-D: IoT Cybersecurity Dataset for AI-Powered Threat Detection in MQTT Networks
This repository presents the MQTTEEB-D dataset, a real-world IoT cybersecurity dataset designed for developing and evaluating AI-powered Intrusion Detection Systems (IDS) in MQTT (Message Queuing Telemetry Transport) networks.

The project explores feature engineering techniques and various machine learning models (Decision Tree, Random Forest, and LSTM) to effectively identify different types of network attacks and anomalies within MQTT traffic. The primary focus is on detecting subtle, resource-efficient attacks that might bypass traditional detection methods.


# Intrusion Detection System for MQTT Networks

## Project Overview

This project focuses on developing an Intrusion Detection System (IDS) specifically tailored for MQTT (Message Queuing Telemetry Transport) networks, which are prevalent in Internet of Things (IoT) ecosystems. The goal is to leverage machine learning techniques, combined with domain-specific feature engineering, to accurately identify various types of cyberattacks targeting MQTT communication. The project demonstrates how carefully crafted features can significantly enhance the detection capabilities of an IDS, particularly for subtle and resource-efficient attack patterns that might otherwise go unnoticed.

## Dataset

The dataset used for this project is **MQTTEEB-D: A Real-World IoT Cybersecurity Dataset for AI-Powered Threat Detection in MQTT Networks**.

*   **Citation**: AQACHTOUL, ABDERRAHMANE; KARAM , KHAOULA; ELAMRANI, ABDERRAHMANE; NAJIB, MEHDI ; RAFALIA, NAJAT; BAKHOUYA, MOHAMED (2025), “MQTTEEB-D: A Real-World IoT Cybersecurity Dataset for AI-Powered Threat Detection in MQTT Networks”, Mendeley Data, V1, doi: 10.17632/jfttfjn6tr.1

The dataset comprises `222,813` network traffic records across 13 original features, including `timestamp`, `tcp_flags`, `tcp_time_delta`, `tcp_len`, and various MQTT-specific parameters (`mqtt_conack_flags`, `mqtt_conflag_cleansess`, `mqtt_conflags`, `mqtt_dupflag`, `mqtt_hdrflags`, `mqtt_kalive`, `mqtt_msg`, `mqtt_qos`). A `Target` column (ranging from 0 to 5) labels the type of network behavior/attack, where `0` typically represents normal traffic.

## Initial Data Analysis

Initial exploration of the dataset revealed:

*   **Shape**: `(222,813, 13)` indicating a substantial number of records.
*   **Data Types**: A mix of `object` (timestamp), `int64`, and `float64` types.
*   **Missing Values**: No missing values were found, simplifying initial preprocessing.
*   **Descriptive Statistics**: Key observations included:
    *   `tcp_time_delta`: Relatively concentrated, suggesting events within specific timeframes.
    *   `tcp_len`: Highly variable, with a right-skewed distribution, indicating many small packets and fewer large ones. This variability is a strong indicator for anomaly detection.
    *   `mqtt_dupflag`: Identified as a constant feature with a value of `0.0` across all records, implying redundancy for predictive modeling.
    *   `mqtt_kalive`: Showed common values at `0.0` and `60.0`, suggesting bimodal behavior.
    *   `mqtt_msg`: Exhibited a high maximum value and standard deviation, pointing to instances of extremely large message counts, potentially anomalous.

### Box Plot Analysis (`tcp_len` and `mqtt_msg` by `Target`)

Visualizing `tcp_len` and `mqtt_msg` distributions across different `Target` classes provided crucial insights:

*   **Target 3 (Subtle Attack)**: Stood out with exceptionally low `tcp_len` and near-zero `mqtt_msg` values, indicating an attack type characterized by very small, potentially numerous, non-MQTT control packets.
*   **Targets 1 & 2 (High-Volume MQTT Attacks)**: Exhibited significantly higher `mqtt_msg` counts and wider `tcp_len` distributions compared to normal traffic, suggesting large message volumes and varied packet sizes.
*   **Target 0 (Normal Behavior)**: Showed concentrated distributions at lower `mqtt_msg` counts and medium `tcp_len` values.

## Feature Engineering Strategies

Based on the initial analysis, several domain-specific features were engineered to enhance the model's ability to discriminate between normal and malicious traffic:

1.  **Categorical Bins**: Created `tcp_len_category` ('small', 'medium', 'large') and `mqtt_msg_category` ('none', 'low', 'moderate', 'high') to capture distinct thresholds observed in the box plots.
2.  **Interaction Features**: Calculated `mqtt_msg_per_tcp_len` (ratio) and `tcp_len_mqtt_msg_product` to uncover relationships between message volume and packet size.
3.  **Derived Features**: Extracted specific patterns from existing columns:
    *   `unusual_tcp_flags`: Binary indicator for rare `tcp_flags` combinations.
    *   `mqtt_conflags_anomaly`: Binary indicator for rare `mqtt_conflags` settings.
    *   `mqtt_kalive_deviation`: Binary indicator for `mqtt_kalive` values not equal to `0` or `60`.
    *   `high_mqtt_qos`: Binary indicator for `mqtt_qos` set to `2`.
4.  **Temporal Features**: From the `timestamp` column, `inter_arrival_time`, `time_of_day_seconds`, and `day_of_week` were extracted to capture time-based patterns.
5.  **Feature Removal**: The constant `mqtt_dupflag` column was removed.

## Formulated Hypotheses for IDS Contribution

1.  **Hypothesis 1**: `mqtt_msg` will be a primary discriminator for detecting high-volume **Target 1** and **Target 2** attacks.
2.  **Hypothesis 2**: The combination of exceptionally low `tcp_len` and near-zero `mqtt_msg` will uniquely identify **Target 3** attacks.
3.  **Hypothesis 3**: Engineered features from `timestamp` will provide critical context for detecting time-based attack patterns.
4.  **Hypothesis 4**: The constant `mqtt_dupflag` feature can be safely removed, simplifying the model.

## Model Training and Evaluation

Two types of machine learning models (Decision Tree and RandomForestClassifier) were trained and evaluated on both the original (baseline) and engineered feature sets to assess the impact of feature engineering.

### Performance Summary (F1-scores)

| Metric        | Baseline DT | Enhanced DT | Baseline RF | Enhanced RF |
| :------------ | :---------- | :---------- | :---------- | :---------- |
| **Accuracy**  | 0.92        | 0.96        | 0.91        | 0.95        |
| **Macro Avg F1** | 0.85        | 0.94        | 0.83        | 0.92        |
| **F1-score Target 0** | 0.85        | 0.93        | 0.85        | 0.91        |
| **F1-score Target 3** | **0.32**    | **0.82**    | **0.29**    | **0.71**    |

### Key Findings from Model Comparison

1.  **Overall Performance**: Enhanced models consistently outperformed their baseline counterparts. The **Enhanced Decision Tree** achieved the highest accuracy (0.96) and macro F1-score (0.94) among all models, showcasing the significant positive impact of feature engineering regardless of the model type.
2.  **Impact on Target 3 (Hypothesis 2 Validation)**: The most striking improvement was observed for `Target 3` attacks. The F1-score for `Target 3` dramatically increased from `0.32` to `0.82` (+0.50 improvement) for the Decision Tree, and from `0.29` to `0.71` (+0.42 improvement) for the RandomForest. This strongly validates Hypothesis 2, demonstrating that the engineered features successfully enabled the detection of these subtle, low-activity intrusions that baseline models failed to identify.
3.  **Consistency of Engineered Features**: The engineered features consistently led to significant performance improvements across both Decision Tree and RandomForest models, reinforcing their value for detecting challenging attack types.
4.  **Model Robustness**: While RandomForest is generally considered more robust, the Enhanced Decision Tree achieved slightly better overall results than the Enhanced RandomForest in this specific context. This suggests that for this dataset and feature set, a single well-structured Decision Tree (benefiting from engineered features) was highly effective.
5.  **Impact on Target 0 (Normal Behavior)**: Both models showed improved detection of `Target 0` (normal traffic) with engineered features, suggesting better differentiation from anomalous patterns.

## Unique Contribution

The project's most significant and unique contribution lies in the **consistent and dramatic improvement in detecting 'Target 3' attacks** through **domain-specific feature engineering**. These attacks, characterized by exceptionally low `tcp_len` and near-zero `mqtt_msg` counts, are often difficult to identify with standard feature sets. Our approach transformed `Target 3` from a poorly detected class (F1-scores around 0.3) into a moderately well-detected one (F1-scores up to 0.82). This highlights a novel approach to identifying **subtle, resource-efficient attacks** in MQTT-based IoT environments, which is crucial for modern IDS that need to look beyond high-volume anomalies and address nuanced protocol abuses.

## Future Work and Refinements

1.  **Hyperparameter Tuning and Model Optimization**: Systematically tune hyperparameters for all models (Decision Tree, RandomForest, and the newly introduced LSTM) using techniques like GridSearchCV or RandomizedSearchCV to maximize performance across all target classes.
2.  **Exploration of Advanced Machine Learning Models**: Investigate advanced ensemble methods (e.g., XGBoost, LightGBM) and deep learning architectures like Recurrent Neural Networks (RNNs) or Convolutional Neural Networks (CNNs), especially if more complex sequential or temporal patterns are to be explored.
3.  **Real-time Detection Capabilities**: Explore integrating the trained IDS model into stream processing frameworks (e.g., Apache Kafka, Apache Flink) for real-time analysis and immediate alerting, potentially refining temporal features with advanced windowing techniques.
4.  **Deployment and Continuous Monitoring**: Consider edge deployment for minimizing latency, develop robust alerting mechanisms, and establish a continuous feedback loop for model retraining with new labeled data to ensure adaptability to evolving threats.
5.  **Dataset Expansion and Feature Enhancement**: Explore integrating external threat intelligence and conducting deeper, more granular analysis of MQTT and TCP protocol fields to engineer even more nuanced features.

# LSTM Model Performance

An LSTM model was also designed, trained, and evaluated on the sequential data. While the overall accuracy was `0.8974`, the F1-score for `Target 3` was `0.23`, indicating that the specific LSTM architecture and training parameters used struggled with this subtle attack type more than the enhanced tree-based models. This suggests that further optimization of the LSTM architecture, hyperparameter tuning, or potentially different sequential feature representations might be necessary to leverage its full potential for time-series anomaly detection in this context.
