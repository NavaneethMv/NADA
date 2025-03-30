import numpy as np
from model.preprocessing import DataPreprocessor
from backend.model.model_arc import NetworkArchitecture
from model.main import load_data
from sklearn.preprocessing import LabelEncoder

def main():
    try:
        df_train, df_test = load_data('KDDTrain+.txt', 'KDDTest+.txt')
        preprocessor = DataPreprocessor(df_train, df_test)
        X_train, X_val, y_train, y_val, X_test, y_test = preprocessor.process()
        
        input_shape = (X_train.shape[1],)
        
        if len(y_train.shape) == 1:
            le = LabelEncoder()
            y_train = le.fit_transform(y_train)
            y_val = le.transform(y_val)
            num_classes = len(np.unique(y_train))
            
            y_train = np.eye(num_classes)[y_train]
            y_val = np.eye(num_classes)[y_val]
        else:
            num_classes = y_train.shape[1]
        
        model = NetworkArchitecture.build_cnn_model(input_shape, num_classes)
        print("Loading weights...")
        model.load_weights('best_model.h5')
        
        print("Making predictions on validation set...")
        predictions = model.predict(X_val)
        
        predicted_classes = np.argmax(predictions, axis=1)
        true_classes = np.argmax(y_val, axis=1)
        
        accuracy = np.mean(predicted_classes == true_classes)
        print(f"\nValidation Accuracy: {accuracy:.4f}")
        
        print("\nSample predictions (first 5):")
        for i in range(10):
            print(f"Sample {i+1}: Predicted: {predicted_classes[i]}, Actual: {true_classes[i]}")
        
        return model, predictions, predicted_classes, true_classes
    
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        raise

if __name__ == "__main__":
    model, predictions, pred_classes, true_classes = main()