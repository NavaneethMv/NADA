import tensorflow as tf
from tensorflow.keras import layers, models

class NetworkArchitecture:
    @staticmethod
    def build_cnn_model(input_shape, num_classes):
        """Build and return the CNN model"""
        inputs = layers.Input(shape=input_shape)
        
        
        x = layers.Reshape((input_shape[0], 1))(inputs)
        
        
        x = NetworkArchitecture._create_cnn_block(x, 64)
        
        
        x = NetworkArchitecture._create_cnn_block(x, 128)
        
        
        x = NetworkArchitecture._create_cnn_block(x, 256, include_pool=False)
        
        
        x = layers.GlobalAveragePooling1D()(x)
        x = NetworkArchitecture._create_dense_block(x, 256)
        x = NetworkArchitecture._create_dense_block(x, 128)
        
        
        outputs = layers.Dense(num_classes, activation='softmax')(x)
        
        model = models.Model(inputs=inputs, outputs=outputs)
        
        
        initial_learning_rate = 0.001
        lr_schedule = tf.keras.optimizers.schedules.ExponentialDecay(
            initial_learning_rate, decay_steps=1000, decay_rate=0.9
        )
        optimizer = tf.keras.optimizers.Adam(learning_rate=lr_schedule)
        
        model.compile(
            optimizer=optimizer,
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    @staticmethod
    def _create_cnn_block(x, filters, include_pool=True):
        """Create a CNN block with batch normalization and dropout"""
        x = layers.Conv1D(filters, 3, padding='same')(x)
        x = layers.BatchNormalization()(x)
        x = layers.Activation('relu')(x)
        x = layers.Dropout(0.2)(x)
        if include_pool:
            x = layers.MaxPooling1D(pool_size=2)(x)
        return x
    
    @staticmethod
    def _create_dense_block(x, units):
        """Create a dense block with batch normalization and dropout"""
        x = layers.Dense(units, activation='relu')(x)
        x = layers.BatchNormalization()(x)
        x = layers.Dropout(0.5)(x)
        return x
