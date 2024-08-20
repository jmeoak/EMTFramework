# EMTFramework



## An EMBER Static Malware Analysis Tactical Decision Aid for Incident Responders

## Installation
The EMT Framework is composed of 5 parts. The Model Trainer, Model Evaluator, EMT Framework Main, VirusTotal Integrator, and Post Processing Module (visualized below) All of the parts are available as Jupyter notebooks except for the EMT Framework Main which is available as a python file. These can be downloaded at https://github.com/jmeoak/EMTFramework

<img src="https://github.com/jmeoak/EMTFramework/blob/main/EMT_Flowchart.png" width="400">


### Jupyter:
The 4 Jupyter notebook parts can be run in any environment setup to run jupyter. In order to use the VirusTotal Integrator, a VirusTotal API key is needed. A version is included with free accounts, but is limited to 4 requests per minute and 500 per day so testing may need to be spread over multiple days if using the free version. The environment must satisfy the following dependencies:

- EMBER: https://github.com/elastic/ember (the setup script currently does not work. When installing, updated the requirements document line lief==0.9.0 to be lief>=0.9.0). The other dependencies (tqdm, numpy, pandas, lightgbm, and scikit-learn) are required by ember module and most are used in the ember framework
- TensorFlow: https://www.tensorflow.org/ (In jupyter execute !pip install tensorflow)
- VirusTotal API: https://github.com/VirusTotal/vt-py
- Standard libraries already available in most jupyter environments: joblib, re, matplotlib