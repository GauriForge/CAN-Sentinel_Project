# **CAN-Sentinel**



## **Intelligent CAN Bus Intrusion Detection and Security Monitoring System**



###### CAN-Sentinel is a cybersecurity project designed to monitor Controller Area Network (CAN) traffic, detect suspicious communication patterns, classify potential attacks, assess threat severity, visualize security events, and generate a security report.

###### 

###### The project uses simulated CAN traffic so that CAN-bus security concepts can be studied and tested safely without connecting to a real vehicle or physical ECU.



### **Project Overview:-**



###### Controller Area Network (CAN) is widely used in automotive systems for communication between Electronic Control Units (ECUs).

###### 

###### Because traditional CAN communication does not provide strong built-in authentication, attackers may inject, flood, replay, or spoof CAN messages.



#### **CAN-Sentinel addresses this problem by creating a complete monitoring and detection pipeline:**





###### CAN Traffic Simulation

###### &#x20;       ↓

###### CAN Traffic Sniffing

###### &#x20;       ↓

###### Feature Extraction

###### &#x20;       ↓

###### Rule-Based Detection

###### &#x20;       ↓

###### Machine Learning Detection

###### &#x20;       ↓

###### Threat Severity Analysis

###### &#x20;       ↓

###### ECU / CAN-ID Mapping

###### &#x20;       ↓

###### Dashboard \& Alerts

###### &#x20;       ↓

###### Attack Timeline

###### &#x20;       ↓

###### Security Report





### **Objectives:-**



#### The main objectives of CAN-Sentinel are:



* ###### Simulate normal CAN traffic.
* ###### Simulate abnormal CAN traffic and attack scenarios.
* ###### Capture and store CAN frames.
* ###### Extract useful security-related features.
* ###### Detect suspicious CAN traffic using predefined rules.
* ###### Detect anomalies using Machine Learning.
* ###### Combine rule-based and ML detection evidence.
* ###### Assign threat severity levels.
* ###### Map suspicious CAN IDs to corresponding ECU information.
* ###### Display security information through a graphical dashboard.
* ###### Maintain an attack timeline.
* ###### Generate a security report in PDF format.
* ###### Provide a modular architecture that can be extended in the future.







### **Key Features:-**



1. #### **CAN Traffic Simulation**



##### **The simulator generates CAN messages representing different vehicle functions, including:**

* ###### Engine RPM
* ###### Vehicle Speed
* ###### Engine Temperature
* ###### Brake Status
* ###### Steering Angle



##### **It also supports abnormal traffic scenarios such as:**

* ###### CAN flooding
* ###### CAN message spoofing





#### **2. CAN Traffic Sniffing**



##### **The CAN sniffer captures CAN frames and records:**

* ###### Timestamp
* ###### CAN ID
* ###### DLC
* ###### Payload
* ###### Label
* ###### Attack type



###### Captured traffic is stored in CSV format for further analysis.



#### **3. Feature Extraction**



##### **CAN-Sentinel extracts features from CAN traffic including:**

* ###### CAN ID
* ###### DLC
* ###### Timestamp
* ###### Individual payload bytes
* ###### Payload sum
* ###### Payload mean
* ###### Payload maximum
* ###### Payload minimum
* ###### Number of non-zero bytes
* ###### Message frequency
* ###### Time interval
* ###### Repeated-message indication



###### These features are used by the detection modules.



#### **4. Rule-Based Detection**



##### **The rule detector checks CAN traffic for suspicious patterns such as:**



* ###### Abnormally high message frequency
* ###### Very short message intervals
* ###### Suspicious payload values
* ###### Repeated messages
* ###### Other predefined CAN traffic anomalies



###### The rule engine produces a rule score and individual rule indicators.



#### **5. Machine Learning Detection**



* ###### CAN-Sentinel uses an anomaly-detection approach based on Isolation Forest.
* ###### The ML detector analyzes extracted CAN traffic features and identifies traffic that differs significantly from normal communication patterns.
* ###### The ML result is combined with rule-based evidence to improve detection reliability.



#### **6. Threat Severity**



##### **Detected threats are classified into four severity levels:**

* ###### Low
* ###### Medium
* ###### High
* ###### Critical



##### **Severity is determined using factors such as:**

* ###### Rule score
* ###### Message frequency
* ###### Timing anomalies
* ###### Payload anomalies
* ###### Repeated messages
* ###### ML anomaly detection



###### Each suspicious event also receives a short explanation of why it was considered threatening.





#### **7. CAN-ID / ECU Mapping**



###### CAN-Sentinel maintains a mapping between CAN IDs and their corresponding vehicle functions and ECUs. This allows the system to identify the purpose of a CAN message and the ECU associated with it.



* ###### **0x100 — Engine RPM**

###### Message: Engine RPM

###### ECU: Engine ECU



* ###### **0x101 — Vehicle Speed**

###### Message: Vehicle Speed

###### ECU: Transmission ECU



* ###### **0x102 — Engine Temperature**

###### Message: Engine Temperature

###### ECU: Engine ECU



* ###### **0x103 — Brake Status**

###### Message: Brake Status

###### ECU: Brake ECU



* ###### **0x104 — Steering Angle**

###### Message: Steering Angle

###### ECU: Steering ECU



###### This mapping allows the dashboard and security reports to provide meaningful information about suspicious CAN messages instead of displaying only hexadecimal CAN IDs.

###### 

###### &#x20;



### **Dashboard:-**



##### CAN-Sentinel includes a PyQt5-based graphical security monitoring dashboard for viewing CAN-bus traffic and detected security events.



##### **The dashboard provides:**



* ###### Total CAN traffic count
* ###### Normal traffic count
* ###### Suspicious traffic count
* ###### High and Critical threat count
* ###### CAN ID information
* ###### Message name
* ###### ECU information
* ###### Attack type
* ###### ML detection result
* ###### Rule detection result
* ###### Rule score
* ###### Threat severity
* ###### Threat reason
* ###### Latest security event
* ###### Selected suspicious event details
* ###### Traffic refresh functionality



###### The dashboard acts as the main visualization interface of CAN-Sentinel and allows security events to be reviewed without directly examining the generated CSV files.







### **Alert Management:-**



##### The Alert Manager processes detected suspicious CAN traffic and creates structured security alerts.



##### **The alert system records:**



* ###### Timestamp of the detected event
* ###### CAN ID
* ###### Message name
* ###### Associated ECU
* ###### Attack type
* ###### Detection method
* ###### Threat severity
* ###### Reason for the alert



###### Alerts are stored in a structured CSV file so that they can be used by the dashboard, attack timeline, and security report modules.

###### This provides a centralized way of recording important security events detected by CAN-Sentinel.







### **Attack Timeline:-**



##### The Attack Timeline module records suspicious security events in chronological order.



##### **It helps identify:**



* ###### When suspicious activity occurred
* ###### Which CAN ID was involved
* ###### Which ECU was associated with the message
* ###### What type of attack was detected
* ###### The severity of the event
* ###### Why the event was considered suspicious



###### The timeline provides a chronological view of CAN-bus security events and helps in analysing the progression of an attack.

###### The generated timeline data can also be used by the dashboard and security report.







### **Security Report:-**



##### CAN-Sentinel generates a PDF-based security report containing the results of the security analysis.



##### **The report includes:**



* ###### Executive security summary
* ###### Threat severity summary
* ###### Security alerts
* ###### Attack timeline
* ###### Suspicious CAN traffic
* ###### CAN-ID activity
* ###### Detected event types
* ###### Detection methodology
* ###### Security findings
* ###### Final security conclusion



###### The generated report provides a permanent record of the security analysis and can be used for project demonstration, documentation, and security investigation.

###### The report is generated automatically by the report generation module and stored inside the models directory.







### **Complete Detection Workflow:-**



##### The complete CAN-Sentinel workflow follows a modular security-monitoring pipeline.



##### **The overall process is:**



* ###### CAN traffic is generated using the CAN simulator.
* ###### Normal and abnormal traffic are created for testing.
* ###### CAN traffic is captured by the CAN sniffer.
* ###### Captured traffic is stored in structured CSV files.
* ###### Feature Extraction converts raw CAN data into security-related numerical features.
* ###### The Machine Learning module analyses the extracted features and identifies anomalous traffic.
* ###### The Rule Detection module checks the traffic against predefined security rules.
* ###### ML and rule-based results are combined to determine suspicious activity.
* ###### The Threat Severity module assigns Low, Medium, High, or Critical severity.
* ###### The Alert Manager generates structured security alerts.
* ###### The Attack Timeline records suspicious events chronologically.
* ###### The Dashboard displays the detected security events.
* ###### The Report Generator creates the final PDF security report.



###### This modular workflow allows each component to perform a specific security-monitoring task while working together as one complete system.







### **Detection Techniques:-**



##### CAN-Sentinel uses multiple detection techniques instead of depending on a single detection method.



##### **Rule-Based Detection:** Rule-based detection identifies suspicious CAN traffic using predefined security conditions such as:



* ###### Abnormally high message frequency
* ###### Very short message intervals
* ###### Suspicious payload values
* ###### Repeated messages
* ###### Abnormal CAN traffic patterns



###### Rule-based detection is explainable because each alert can be associated with a specific detection rule.





##### **Machine Learning Detection:** 



* ###### CAN-Sentinel uses the Isolation Forest algorithm for anomaly detection.
* ###### The ML model analyses extracted CAN traffic features and identifies observations that differ significantly from normal traffic behaviour.
* ###### The model can detect anomalies without requiring every possible attack pattern to be manually defined.





##### **Combined Detection:** The final detection decision combines rule-based evidence and ML anomaly detection.



##### This improves the reliability of the system because:



* ###### Rules provide explainable security evidence.
* ###### Machine learning identifies unusual behaviour.
* ###### Combining both approaches provides stronger detection results.







### **Attack Scenarios:-**



##### CAN-Sentinel supports simulated abnormal CAN traffic for security testing.



##### **The main attack scenarios include:**



#### **Flooding Attack-**

* ###### A large number of CAN messages are transmitted within a short period of time.
* ###### This can increase bus traffic and affect the normal communication behaviour of other ECUs.
* ###### CAN-Sentinel detects flooding behaviour using traffic frequency and timing-related features.



#### **Spoofing Attack-**

* ###### Fake or manipulated CAN messages are generated using a legitimate CAN ID.
* ###### The attacker attempts to make malicious messages appear as if they originated from a trusted ECU.
* ###### CAN-Sentinel analyses payload behaviour, message patterns, and other extracted features to identify suspicious activity.



###### These attacks are simulated in the virtual CAN environment and are not performed on a real vehicle.







### **CAN Traffic Replay:-**



##### CAN-Sentinel supports the use of previously captured CAN traffic for repeatable security analysis.

##### Recorded normal or abnormal CAN traffic can be used as input for the detection pipeline.



##### **This provides:**

* ###### Repeatable testing
* ###### Easier debugging
* ###### Consistent demonstrations
* ###### Comparison between normal and abnormal traffic
* ###### Testing without requiring a physical vehicle



###### Traffic replay also helps demonstrate the complete CAN-Sentinel workflow in a controlled environment.







### **Project Output Files:-**



##### During execution, CAN-Sentinel generates several structured output files.



##### **Important generated files include:**



* ###### **models/extracted\_features.csv**

###### Contains extracted CAN traffic features.



* ###### **models/anomaly\_results.csv**

###### Contains machine-learning anomaly detection results.



* ###### **models/rule\_detection\_results.csv**

###### Contains rule-based and combined detection results.



* ###### **models/threat\_severity\_results.csv**

###### Contains assigned threat severity and severity reasons.



* ###### **models/security\_alerts.csv**

###### Contains generated security alerts.



* ###### **models/attack\_timeline.csv**

###### Contains chronological security events.



* ###### **models/CAN-Sentinel\_Security\_Report.pdf**

###### Contains the final generated security report.



###### The exact generated files depend on the modules executed during the analysis pipeline.







### **Project Structure:-**



##### The project follows a modular directory structure:



###### CAN-Sentinel-Final/

###### │

###### ├── data/

###### │ ├── normal/

###### │ │ └── normal\_dataset.csv

###### │ └── abnormal/

###### │ └── abnormal\_dataset.csv

###### │

###### ├── models/

###### │

###### ├── src/

###### │ ├── can\_simulator.py

###### │ ├── can\_sniffer.py

###### │ ├── feature\_extraction.py

###### │ ├── anomaly\_detector.py

###### │ ├── rule\_detector.py

###### │ ├── threat\_severity.py

###### │ ├── can\_mapping.py

###### │ ├── dashboard.py

###### │ ├── alert\_manager.py

###### │ ├── attack\_timeline.py

###### │ ├── report\_generator.py

###### │ └── main.py

###### │

###### ├── README.md

###### └── requirements.txt



###### The **data** directory contains normal and abnormal CAN traffic datasets.



###### The **models** directory stores generated detection results, trained model files, alerts, timelines, and security reports.



###### The **src** directory contains the Python implementation of the CAN-Sentinel modules.







### **Technologies Used:-**



##### CAN-Sentinel is implemented using the following technologies:



* ###### Python
* ###### Python-CAN
* ###### SocketCAN
* ###### Virtual CAN (vcan0)
* ###### Pandas
* ###### NumPy
* ###### Scikit-learn
* ###### Isolation Forest
* ###### PyQt5
* ###### ReportLab
* ###### CSV data processing
* ###### Git and GitHub



###### These technologies provide the CAN communication, data-processing, anomaly-detection, graphical-interface, and reporting capabilities required by the project.







### **System Requirements:-**



##### The recommended environment for running the complete CAN-Sentinel system includes:



* ###### Python 3.x
* ###### Linux environment for SocketCAN and vcan0
* ###### Python-CAN
* ###### Pandas
* ###### NumPy
* ###### Scikit-learn
* ###### PyQt5
* ###### ReportLab



###### A Linux environment such as Kali Linux can be used for the virtual CAN setup and final integration testing.



###### The project does not require a physical vehicle or physical ECU for testing.







### **Installation:-**



###### Clone or copy the CAN-Sentinel project to the required system.



###### **Install the required Python dependencies using:**

###### pip install -r requirements.txt



###### **For Linux-based CAN testing, configure the virtual CAN interface:**

###### sudo modprobe vcan

###### sudo ip link add dev vcan0 type vcan

###### sudo ip link set up vcan0



###### **Verify the interface using:**

###### ip link show vcan0



###### After the virtual CAN interface is available, the CAN simulator and sniffer can communicate through vcan0.







### **Running the Project:-**



###### **The complete CAN-Sentinel pipeline can be started using:**

###### python src/main.py



###### The main controller executes the security-analysis modules in sequence.



###### **The general execution order is:**



###### Feature Extraction

###### &#x20;       ↓

###### ML Anomaly Detection

###### &#x20;       ↓

###### Rule Detection

###### &#x20;       ↓

###### Threat Severity

###### &#x20;       ↓

###### Alert Management

###### &#x20;       ↓

###### Attack Timeline

###### &#x20;       ↓

###### Security Report

###### &#x20;       ↓

###### Dashboard



###### Individual modules can also be executed separately when testing or debugging a particular component.







### **Testing:-**



##### CAN-Sentinel can be tested using both normal and abnormal CAN traffic.



##### **Testing includes:**



* ###### Normal CAN traffic analysis
* ###### Flooding attack detection
* ###### Spoofing attack detection
* ###### Message-frequency analysis
* ###### Timing analysis
* ###### Payload analysis
* ###### Repeated-message detection
* ###### Machine-learning anomaly detection
* ###### Rule-based detection
* ###### Threat severity classification
* ###### Alert generation
* ###### Attack timeline generation
* ###### Dashboard visualization
* ###### PDF security report generation



###### Testing is performed in a controlled virtual CAN environment.



### **Security and Safety Considerations:-**



##### CAN-Sentinel is designed for educational, research, and controlled cybersecurity testing.

##### 

##### The project uses simulated CAN traffic and a virtual CAN environment.

##### 

##### **Important safety considerations include:**



* ###### Do not test attack traffic on a real vehicle.
* ###### Do not connect the system to a production vehicle network.
* ###### Use vcan0 or another isolated test environment.
* ###### Use simulated CAN messages for demonstrations.
* ###### Keep abnormal traffic generation inside the controlled laboratory environment.



###### The purpose of the project is to study CAN-bus security monitoring and detection techniques without affecting real automotive systems.







### **Limitations:-**



###### The current version of CAN-Sentinel has several limitations.



* ###### The CAN environment is simulated using a virtual CAN interface.
* ###### The CAN-ID mapping represents a controlled project environment rather than a manufacturer-specific vehicle network.
* ###### Attack scenarios are simulated rather than collected from a real vehicle.
* ###### Machine-learning performance depends on the quality and characteristics of the available dataset.
* ###### The system is intended for monitoring and detection rather than automatically blocking CAN traffic.
* ###### Real automotive networks may contain more complex message structures and timing behaviour.



###### These limitations provide opportunities for future development.







### **Future Enhancements:-**



###### Possible future improvements include:



* ###### Support for additional CAN attack types
* ###### Larger and more diverse CAN datasets
* ###### Real-time machine-learning detection
* ###### Improved anomaly scoring
* ###### Additional vehicle ECU mappings
* ###### Advanced payload analysis
* ###### More detailed attack visualizations
* ###### Real-time CAN traffic graphs
* ###### Automated alert notifications
* ###### Database-based event storage
* ###### Improved security-report analytics
* ###### Support for CAN-FD traffic
* ###### Integration with additional automotive cybersecurity tools
* ###### Evaluation using real-world research datasets



###### These enhancements could improve the scalability and practical applicability of CAN-Sentinel.







### **Conclusion:-**



###### CAN-Sentinel is a modular automotive cybersecurity monitoring system designed to detect suspicious activity in Controller Area Network traffic.



###### The project combines CAN traffic simulation, traffic capture, feature extraction, rule-based detection, machine-learning anomaly detection, threat severity classification, alert management, attack timelines, dashboard visualization, and automated security reporting.



###### By combining multiple detection techniques, CAN-Sentinel provides both automated anomaly identification and explainable security information.



###### The project demonstrates how cybersecurity concepts and machine-learning techniques can be applied to automotive CAN-bus monitoring in a controlled virtual environment.







### **Project Team:-**



###### CAN-Sentinel was developed as a collaborative internship project with responsibilities distributed across different components of the system.



###### **The major project responsibilities included:**



* ###### CAN environment and traffic simulation
* ###### CAN traffic sniffing and data handling
* ###### Detection logic and machine learning
* ###### Dashboard, alerting, timeline, and security reporting
* ###### Integration and final system testing



###### The modular architecture allows the individual components to be developed independently while maintaining a common end-to-end security-analysis workflow.







### **License:-** 



* ###### This project is intended for educational, academic, internship, and research purposes.
* ###### The project should be used only in controlled and authorized environments.

###### 

###### 

