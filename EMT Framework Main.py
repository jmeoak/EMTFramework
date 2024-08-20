#/bin/env/python

import ember
import numpy as np
from joblib import dump, load
import os
import platform
import csv
import lief
import hashlib

print(68 * '-')
print('                  @%%%%%%%%%%%%%                   ')
print('                  %=%%%%%%%%%%%#                   ')
print('                  %=%%%%%%%%%%%#                   ')
print('                  %=%%%%* +%%%%#                   ')
print('       *+%        %=%%%%   %%%%#         %+*       ')
print('      %#%%:#%     %=%%%%+-:%%%%#      %#:%%##      ')
print('     +#%%%%%%-*%  %=%%    #%%%%#   %+=%%%%%%%=     ')
print('   %*%%%%%%%%%%%+=%=% .%- .%%%%#%=*%%%%%%%%%%%*%   ')
print('  %=%%%%%%%%%%%%%%%-% .%: .%%%%+%%%%%%%%%%%%%%%=%  ')
print(' %*%%%%%%%%%%%%%%%%%%%  : :%%%%%%%%%%%%%%%%%%%%%*% ')
print(' %++%%%%%%%%%%%%%%%%%%%.- :%%%%%%%%%%%%%%%%%%%%*+% ')
print('   @%-*%%%%%%%%%%%%%%%%%- : -%%%%%%%%%%%%%%%#-%@       EEEEE  M     M  TTTTT ')
print('       %*-%%%%%%%%%%%%%%= -  %%%%%%%%%%%%=+%           E      MM   MM    T   ')
print('         %%+=%%%%%%%%%%%*=   %%%%%%%%%=+%%             EEE    M M M M    T   ')
print('         %%*=%%%%%%%%%%#   .%%%%%%%%%%=*%%             E      M  M  M    T   ')
print('       %-=%%%%%%%%%%%%%  ##%%%%%%%%%%%%%%+-%           EEEEE  M     M    T   ')
print('   %%-#%%%%%%%%%%%%%%%%=- +%%%%%%%%%%%%%%%%%%-#%                             ')
print(' %-#%%%%%%%%%%%%%%%%%%%%# - %%%%%%%%%%%%%%%%%%%%-% ')
print('  #%%%%%%%%%%%%%%%%%%%%%# - %%%%%%%%%%%%%%%%%%%%#  ')
print('   +*%%%%%%%%%%%%%#:%%%%*  %%%%-#%%%%%%%%%%%%%#+%  ')
print('    ##%%%%%%%%%%=*%=%%%+ =%%%%%=%*-%%%%%%%%%%##    ')
print('     *+%%%%%%:%%  %=%%%#- %%%%%=%  %%:#%%%%%+*     ')
print('      %*%*+#%     %=%%%%% #%%%%=%     %#+*%*%      ')
print('       #%%        %=%%%%% -%%%%=%        %%#       ')
print('                  %=%%%%%=%%%%%=%                  ')
print('                  %=%%%%%%%%%%%=%                  ')
print('                  %=%%%%%%%%%%%=%                  ')
print('                  @%%%%%%%%%%%%%%                  ')
print(68 * '-')
print("Welcome to EMT (EMBER Malware Tactical Descion Aid). ")
print(68 * '-')
print("Uses EMBER Malware Dataset from Elastic. Ref:  H. Anderson and P. Roth, 'EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models', in ArXiv e-prints. Apr. 2018.")
print("https://github.com/elastic/ember")
print(68 * '-')
print('Tool Author: Joel Meoak')
print('https://github.com/jmeoak')
print(68 * '-')

system = platform.system()

if system == 'Windows':
    pathCombine = '\\'
else:
    pathCombine = '/'

useAdv = input("Use Adv Mode? (Dll Detection, Multi-Model) (y/N): ")
if useAdv == '':
    useAdv = 'n' # Default
useAdv = useAdv.lower()

keepAlive = True
while(keepAlive):

    pathToModels = input("Model Directory Path (Def: ./models): ")
    if pathToModels  == '':
        pathToModels = os.getcwd() + pathCombine + 'models'

    if useAdv == 'y':
        modelToRun = input("Choose a model [rf, tree, lgbm, ET, all, manual]: ")
    else:
        modelToRun = input("Choose a model [rf, tree, lgbm, ET]: ")

    if modelToRun == '':
        modelToRun = 'rf' # Default

    roundCut = 0.9

    # Single Model
    if modelToRun != 'all':
        if modelToRun == 'tree':
            modelName = 'tr1.joblib'
        elif modelToRun == 'rf':
            modelName = 'RF9.joblib'
        elif modelToRun == 'ET':
            modelName = 'ET1.joblib'
        elif modelToRun == 'lgbm':
            modelName = 'lgbm.joblib'
            print("This model outputs a prediction between 0 and 1. ")
            roundCutStr = input('Cut point for rounding prediction 0-1 (def: 0.9): ')
            if roundCutStr!='':
                roundCut = np.float32(roundCutStr)
            if roundCut>=1 or roundCut<=0:
                roundCut = 0.9
        else:
            modelName = input('Custom joblib Name: ')

        fullPath = pathToModels + pathCombine + modelName
        print(fullPath)
        model = load(fullPath)
        orgModel = model
        
        print("Single exe/dll or Directory?")
        multipleBool = input("0 file, 1 for dir: ")

        # Single or looping
        if multipleBool != "1":
            # Get path to binary
            print("example: C:\\Users\\joelm\\bash.exe")
            exePath = input("Path: ")
            print(exePath)
            exeData = open(exePath,"rb").read()
            print("Prediction (1 is bad, 0 is good):")
            print(ember.predict_sample(model, exeData))
        else: # Everything in dir specified
            malPath = input("Path to Malware (Def ./malware): ")
            if malPath == '':
                malPath = os.getcwd() + pathCombine + 'malware'
            print(malPath)
            files = os.listdir(malPath)
            print(files)

            fullResults = []
            for i in range(0, len(files)):
                filePath = (malPath + pathCombine + files[i])
                with open(filePath, 'rb') as file:
                    fileData = file.read()
                lief_binary = lief.PE.parse(list(fileData))
                if lief_binary is not None:
                    if useAdv == 'y':
                        lief_binary = lief.PE.parse(list(fileData))
                        exportNumber = 0
                        if lief_binary is not None:
                            exportNumber = len(lief_binary.exported_functions)
                            if exportNumber > 0:
                                modelNameNew = modelName
                                modelNameNewInput = input('Custom dll specifc joblib Name: ')
                                if modelNameNewInput != '':
                                    modelNameNew = modelNameNewInput
                                fullNewModelPath = pathToModels + pathCombine + modelNameNew
                                model = load(fullNewModelPath)
                        hash256 = hashlib.sha256(fileData).hexdigest()
                        result = ember.predict_sample(model, fileData)
                        result = np.where(result >= roundCut, 1, 0)
                        result = int(result)
                        fullResults.append([hash256, files[i], result])
                        print(files[i] + " " + str(result))
                        # restore model
                        model = orgModel
                    else: 
                        result = ember.predict_sample(model, fileData)
                        result = int(result)
                        fullResults.append([files[i], result])
                        print(files[i] + " " + str(result))
                else:
                    print(files[i] + " Not a PE File")
            
            print(fullResults)

            toCsv = input("Write to csv? (y/N): ")
            if toCsv == '':
                toCsv = 'n'
            toCsv = toCsv.lower()

            if toCsv == 'y':
                csvName = input("csv name: ")
                with open(csvName, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['model', modelName])
                    writer.writerows(fullResults)

    # Looping through multiple models
    else:
        print('This will run every model in the directory: ')
        modelsList = os.listdir(pathToModels)
        modelsList = [path for path in modelsList if path.endswith('.joblib')]
        print(modelsList)

        moveForward = input("Continue? (Y/n): ")
        if moveForward == '':
            moveForward = 'y'
        moveForward = moveForward.lower()
        if moveForward == 'n':
            continue
        fullResults = []

        roundCutStr = input('Cut point for rounding prediction 0-1 (def: 0.9): ')
        if roundCutStr!='':
            roundCut = np.float32(roundCutStr)
        if roundCut>=1 or roundCut<=0:
            roundCut = 0.9
        
        malPath = input("Path to Malware (Def ./malware): ")
        if malPath == '':
            malPath = os.getcwd() + pathCombine + 'malware'
        print(malPath)
        files = os.listdir(malPath)
        print(files)

        attacker = input("Name of malware subset? (Def = dir name): ")
        if attacker == '':
            attacker = os.path.basename(malPath)
        print(attacker)

        useDllSpecifier = input("Run Submodel Against DLLs? (y/N): ")
        if useDllSpecifier == '':
            useDllSpecifier = 'n'
        useDllSpecifier = useDllSpecifier.lower()

        # Create the headers for each csv column
        fullResults.append(['Attack/Group', 'Model', 'SHA256 Hash', 'File Name', 'Detected', 'FileType'])
        
        # loop through the list of models
        for j in range(len(modelsList)): 
            print(68 * '-')
            print('Running ' + modelsList[j])
            fullPath = pathToModels + pathCombine + modelsList[j]
            print(fullPath)
            model = load(fullPath)
            orgModel = model

            dllModelName = modelsList[j]
            if useDllSpecifier == 'y':
                dllModelName = input("Dll model to use with " + modelsList[j] + "?: ")
                if dllModelName == '':
                    print("Same model will be used as exe files")
            dllModel = load(pathToModels + pathCombine + dllModelName)

            for i in range(0, len(files)):
                filePath = (malPath + pathCombine + files[i])
                if os.path.isdir(filePath):
                    print(filePath + ' this is a dir')
                    continue
                with open(filePath, 'rb') as file:
                    fileData = file.read()
                # Get hash of binary
                hash256 = hashlib.sha256(fileData).hexdigest()

                # Parse binary to detemine if PE and use for exe or dll detection
                lief_binary = lief.PE.parse(list(fileData))

                if lief_binary is not None:
                    # if useDLLSpecifier it can use a different model for dlls vs exes
                    # it also includes this in the csv for data analysis on dll vs exe performance
                    FileType = 'exe'
                    exportNumber = 0
                    exportNumber = len(lief_binary.exported_functions)
                    if exportNumber > 0:
                        FileType = 'dll'
                    if useDllSpecifier == 'y':
                        modelNameTemp = modelsList[j]
                        if exportNumber > 0:
                            model = dllModel
                            modelNameTemp = dllModelName
                        result = ember.predict_sample(model, fileData)
                        result = int(result)
                        # Append row for csv
                        fullResults.append([attacker, modelNameTemp[j], hash256, files[i], result, FileType])
                        print(files[i] + " " + str(result) + " " + FileType)
                        
                        # restore orgModel
                        model = orgModel
                    else: 
                        result = ember.predict_sample(model, fileData)
                        result = int(result)
                        # Append row for csv
                        fullResults.append([attacker, modelsList[j], hash256, files[i], result, FileType])
                        print(files[i] + " " + str(result))
                else:
                    print(files[i] + " Not a PE File")
            
        toCsv = input("Write to csv? (Y/n): ")
        if toCsv == '':
            toCsv = 'y'
        toCsv = toCsv.lower()

        if toCsv == 'y':
            csvName = input("csv name (def: malware subset name): ")
            if csvName == '':
                csvName = attacker + '_results.csv'
            if os.path.isfile(csvName):
                with open(csvName, mode='a', newline='') as file:
                    fullResults = fullResults[1:]
                    writer = csv.writer(file)
                    writer.writerows(fullResults)
            else:
                with open(csvName, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerows(fullResults)

    # Breakout
    restart = input("Run Again? (Y/n) ")
    if restart == '':
        restart = 'y'
    restart = restart.lower()
    if restart != 'y':
        keepAlive = False
