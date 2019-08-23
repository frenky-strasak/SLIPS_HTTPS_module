import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
# pip install tensorflow==2.0.0-beta1
import tensorflow as tf
import numpy as np


class TFModel:

    def __init__(self, path_to_model: str):
        self.path_to_model = path_to_model
        self.MAX_LENGTH_SAMPLE = 250
        self.model = None

    def load_model(self):
        # Load model from file.
        self.model: tf.keras.models.Model = tf.keras.models.load_model(self.path_to_model)
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(),
            loss=tf.keras.losses.SparseCategoricalCrossentropy(),
            metrics=[tf.keras.metrics.SparseCategoricalAccuracy(name="accuracy")],
        )

    def predict_sample(self, sample: list) -> int:
        sample = self.__prepare_sample(sample)
        _y = self.model.predict(sample, batch_size=1)
        _y = np.argmax(_y)
        return _y

    def __prepare_sample(self, sample: list) -> np.ndarray:
        sample = np.array(sample)
        sample = sample[:self.MAX_LENGTH_SAMPLE]
        return sample
