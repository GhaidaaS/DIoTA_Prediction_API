import json
import csv
import pandas as pd
import numpy as np
from keras import models
from sklearn.preprocessing import StandardScaler
class Predict:
  data = {}
  def __init__(self, req_data):
    self.data = req_data

  def run(self, data):
    self.create_csv_file(data)
    result = self.run_model()
    final_result = self.get_final_result(result)
    return  final_result

  def create_csv_file(self, req_data):
    # ---- covert data to csv ----
    # Opening JSON file and loading the data
    # into the variable data
    network_data = req_data['data']

    # now we will open a file for writing
    data_file = open('data/data.csv', 'w')

    # create the csv writer object
    csv_writer = csv.writer(data_file)

    # Counter variable used for writing
    # headers to the CSV file
    count = 0

    for flow in network_data:
      if count == 0:
        # Writing headers of CSV file
        header = flow.keys()
        csv_writer.writerow(header)
        count += 1

      # Writing data of CSV file
      csv_writer.writerow(flow.values())
    data_file.close()


  # ----- Get Final result function -----
  def get_final_result(self, result_file):
  #---- create two diffrent files "attacks.csv" & "statistics.csv" -----
  # now we will open a file
    df = pd.read_csv('data/Model_result.csv')
    # attacks.csv
    total_dos= 0
    total_ddos= 0
    total_theft= 0
    total_reconnaissance= 0
    total_records= 0
    total_attacks= 0
    total_normal= 0
    # create a list to store results
    attacks_list = []
    # read the file
    # for every line in the csv
    for row in df.itertuples():
      #create a user dict
      total_records +=1
      if row.category != "Normal":
        attack = {
          'pkSeqID': row.pkSeqID,
          'saddr': row.saddr,
          'sport': row.sport,
          'daddr': row.daddr,
          'dport': row.dport,
          'dur': row.dur,
          'stime': row.stime,
          'ltime': row.ltime,
          'attack_type': row.category,
        }
        # add this user to the list of users
        attacks_list.append(attack)
        if row.category == "DoS":
            total_dos +=1
        elif row.category == "DDoS":
            total_ddos +=1
        elif row.category == "Theft":
            total_theft +=1
        elif row.category == "Reconnaissance":
            total_reconnaissance +=1
      else:
        total_normal += 1
    # creation of statistics file
    # calculate statistics data

    # ---- convert "attacks.csv" & "statistics.csv" to json ----
    data = {
      'statistics': {
        'total_records': total_records,
        'total_attacks': total_records - total_normal,
        'total_ddos': total_ddos,
        'total_dos': total_dos,
        'total_theft': total_theft,
        'total_reconnaissance': total_reconnaissance,
      },
      'attacks': attacks_list
    }

    return data

  # -----run modle and get prediction data function-----
  def run_model(self):
    # read dataset
    user_data = pd.read_csv('data/data.csv')
    df=user_data[['TnP_PerProto', 'TnBPSrcIP', 'TnBPDstIP', 'spkts', 'pkts', 'TnP_PSrcIP',
                 'sbytes', 'bytes', 'TnP_PDstIP', 'TnP_Per_Dport', 'sum', 'dpkts',
                 'dbytes', 'Pkts_P_State_P_Protocol_P_DestIP', 'dur', 'srate',
                 'Pkts_P_State_P_Protocol_P_SrcIP', 'stime', 'ltime','N_IN_Conn_P_DstIP']]
    # load model
    LSTM_Model_anova = models.load_model('Multi_LSTM_Model_Anovat.h5')
    # convert the data to np.arrays
    df = np.array(df)
    # scaler the data
    sc = StandardScaler()
    df = sc.fit_transform(df)
    # reshape the data to be 3D
    timesteps=1
    df = np.reshape(df, (df.shape[0], timesteps, df.shape[1]))
    # predicting the type of traffics
    predict = LSTM_Model_anova.predict_classes(df)
    predictn = predict.flatten().round()
    predictn = predictn.tolist()
    for i in range(len(predictn)):
        if predictn[i] == 0:
            predictn[i] = 'Reconnaissance'
        elif predictn[i] == 1:
            predictn[i] = 'Normal'
        elif predictn[i] == 2:
            predictn[i] = 'Theft'
        elif predictn[i] == 3:
            predictn[i] = 'DDoS'
        elif predictn[i] == 4:
            predictn[i] = 'DoS'
    #convert prediction ot dataframe
    predicted_df = pd.DataFrame(data=predictn, columns=['category'], index=user_data.index.copy())
    # join predicted_df & user_data
    result_file = pd.merge(user_data, predicted_df, how ='left', left_index=True,right_index=True)
    #return result_file
    result_file.to_csv('data/Model_result.csv')

    return result_file
