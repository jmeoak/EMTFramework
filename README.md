# EMTFramework



## An EMBER Static Malware Analysis Tactical Decision Aid for Incident Responders

## Installation
The EMT Framework is composed of 5 parts. The Model Trainer, Model Evaluator, EMT Framework Main, VirusTotal Integrator, and Post Processing Module (visualized below) All of the parts are available as Jupyter notebooks except for the EMT Framework Main which is available as a python file. These can be downloaded at https://github.com/jmeoak/EMTFramework

<img src="https://github.com/jmeoak/EMTFramework/blob/main/EMT_Flowchart.png" width="350">


### Jupyter:
The 4 Jupyter notebook parts can be run in any environment setup to run jupyter. In order to use the VirusTotal Integrator, a VirusTotal API key is needed. A version is included with free accounts, but is limited to 4 requests per minute and 500 per day so testing may need to be spread over multiple days if using the free version. The environment must satisfy the following dependencies:

- EMBER: https://github.com/elastic/ember (the setup script currently does not work. When installing, updated the requirements document line lief==0.9.0 to be lief>=0.9.0). The other dependencies (tqdm, numpy, pandas, lightgbm, and scikit-learn) are required by ember module and most are used in the ember framework
- TensorFlow: https://www.tensorflow.org/ (In jupyter execute !pip install tensorflow)
- VirusTotal API: https://github.com/VirusTotal/vt-py
- Standard libraries already available in most jupyter environments: joblib, re, matplotlib


#### Model Trainer:
This is the largest of the notebooks in the EMT framework. It is used to train new models for use as the machine learning engine. Examples are shown along with comments on the code. The EMBER training data must be in vectorized form. The https://github.com/elastic/ember has instructions on doing this, and it is recommended to do the vectorization in a command line environment or separate notebook as it only needs to be done once.

#### Model Evaluator:
This notebook uses the testing samples from the EMBER dataset to evaluate each model and output standard machine learning metrics. It is recommended to be careful of models with extremely high accuracy scores as these have been shown to be overfit to the EMBER dataset for use in modern malware detection.
#### VirusTotal Integrator:
This notebook takes in a csv file output by the EMT Framework Main, queries VirusTotal using the SHA256 hash and creates a new csv file including all of the original data in addition to adding the VirusTotal score corresponding to each sample. A VirusTotal API key is needed for this notebook.
#### Post Processing Module:
This notebook accepts either the csv file output by the EMT Framework Main or the VirusTotal Integrator and shows accuracy metrics to include normal accuracy and adjusted accuracy using predicted FPR.

### EMT Framework Main:
The EMT Framework Main runs as a stand-alone python script. It has 2 run modes, normal and advanced. It uses the following folder structure by default where there is one folder at the same level as the python script containing the joblib models and another containing all of the malware samples.
- EMT_Main.py
- models/
- malware/

#### Standard Mode: 
Provides prompts for each option and runs a single model against 1 or more binaries with the option to save to csv. Designed for use in incident response
#### Advanced Mode:
Shown in screenshots below. This mode allows detection of DLLs and can run different models against DLLs in addition to the ability to run multiple models at once. Designed for research use cases.

#### Options Using Advanced Mode:
#### Model: 
The ‘all’ options will use every model in the model folder provided. The 4 names included in list shown will run already trained Random Forest, Decision Tree, EMBER Pretrained LightGBM, or Extremely Random Forest. Manual allows a custom name to input corresponding to a new trained model in joblib format.
#### Cut point: 
Some models provide a likelihood score between 1 and 0. This number cut point is used in the case of likelihood. 0.9 means the models needs to be 90% confident that the sample is malicious for classification as malware.
#### Path to malware folder: 
Custom path of /root/venv/Malware/pentesting/msf/stager used in the screenshot. Auto detection of PE files is done so this can be run against folders containing a mix of PE, doc, pdf, or other types of malware and will only run against PE files.
#### Name of malware subset:
This will be the attack/group/tool family. Included as first column of csv document.

#### Run different models against DLLs: 
This is best when running multiple models as it will ask for a new DLL sub model to run with every loop of a new model. The better option is to use this with execution of a single model.

