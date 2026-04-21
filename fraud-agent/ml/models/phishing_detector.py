"""ML module for fraud detection model training and conversion."""
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """Configuration for model training."""
    max_length: int = 256
    batch_size: int = 32
    epochs: int = 10
    learning_rate: float = 2e-5
    warmup_steps: int = 500
    model_name: str = "distilbert-base-uncased"
    num_labels: int = 2
    output_dir: str = "./models"


@dataclass
class InferenceResult:
    """Result from model inference."""
    scores: np.ndarray
    predicted_class: int
    confidence: float
    class_probabilities: np.ndarray


class PhishingDetectorModel:
    """Phishing detection model wrapper.
    
    This class provides a unified interface for running inference
    with either ONNX or TFLite models.
    """
    
    def __init__(
        self,
        model_path: str,
        model_type: str = "onnx",
        tokenizer_path: Optional[str] = None,
    ):
        """Initialize the model.
        
        Args:
            model_path: Path to the model file
            model_type: Type of model ("onnx" or "tflite")
            tokenizer_path: Path to tokenizer (for ONNX only)
        """
        self.model_path = model_path
        self.model_type = model_type
        self.tokenizer_path = tokenizer_path
        self._session = None
        
        self._load_model()
    
    def _load_model(self) -> None:
        """Load the model based on type."""
        if self.model_type == "onnx":
            self._load_onnx_model()
        elif self.model_type == "tflite":
            self._load_tflite_model()
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def _load_onnx_model(self) -> None:
        """Load ONNX model using ONNX Runtime."""
        try:
            import onnxruntime as ort
        except ImportError:
            logger.warning("ONNX Runtime not installed, model loading deferred")
            return
        
        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = (
            ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        )
        sess_options.intra_op_num_threads = 4
        sess_options.inter_op_num_threads = 4
        
        self._session = ort.InferenceSession(
            self.model_path,
            sess_options,
            providers=["CPUExecutionProvider"],
        )
        
        self._input_name = self._session.get_inputs()[0].name
        self._output_name = self._session.get_outputs()[0].name
        
        logger.info(f"ONNX model loaded from {self.model_path}")
    
    def _load_tflite_model(self) -> None:
        """Load TFLite model."""
        try:
            import tflite_runtime.interpreter as tflite
        except ImportError:
            try:
                import tensorflow as tf
                tflite = tf.lite
            except ImportError:
                logger.warning("TFLite support not available")
                return
        
        self._interpreter = tflite.Interpreter(model_path=self.model_path)
        self._interpreter.allocate_tensors()
        
        self._input_details = self._interpreter.get_input_details()
        self._output_details = self._interpreter.get_output_details()
        
        logger.info(f"TFLite model loaded from {self.model_path}")
    
    def predict(self, text: str) -> InferenceResult:
        """Run inference on text input.
        
        Args:
            text: Input text to classify
            
        Returns:
            InferenceResult with scores and predictions
        """
        if self.model_type == "onnx":
            return self._predict_onnx(text)
        elif self.model_type == "tflite":
            return self._predict_tflite(text)
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def _predict_onnx(self, text: str) -> InferenceResult:
        """Run ONNX inference."""
        import onnxruntime as ort
        
        input_ids, attention_mask = self._tokenize(text)
        
        ort_inputs = {
            self._input_name: input_ids,
            "attention_mask": attention_mask,
        }
        
        outputs = self._session.run([self._output_name], ort_inputs)[0]
        
        return self._process_outputs(outputs)
    
    def _predict_tflite(self, text: str) -> InferenceResult:
        """Run TFLite inference."""
        input_ids, attention_mask = self._tokenize(text)
        
        self._interpreter.set_tensor(
            self._input_details[0]["index"], input_ids
        )
        self._interpreter.set_tensor(
            self._input_details[1]["index"], attention_mask
        )
        
        self._interpreter.invoke()
        
        outputs = self._interpreter.get_tensor(
            self._output_details[0]["index"]
        )
        
        return self._process_outputs(outputs)
    
    def _tokenize(
        self, text: str
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Tokenize text input."""
        from .tokenizer import SimpleTokenizer
        
        tokenizer = SimpleTokenizer(max_length=256)
        return tokenizer.encode(text)
    
    def _process_outputs(self, outputs: np.ndarray) -> InferenceResult:
        """Process model outputs."""
        probabilities = self._softmax(outputs[0])
        predicted_class = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_class])
        
        return InferenceResult(
            scores=outputs[0],
            predicted_class=predicted_class,
            confidence=confidence,
            class_probabilities=probabilities,
        )
    
    @staticmethod
    def _softmax(x: np.ndarray) -> np.ndarray:
        """Compute softmax probabilities."""
        exp_x = np.exp(x - np.max(x))
        return exp_x / exp_x.sum()


class SimpleTokenizer:
    """Simple tokenizer for text preprocessing.
    
    Provides basic tokenization without external dependencies.
    """
    
    VOCAB = {
        "[PAD]": 0,
        "[UNK]": 1,
        "[CLS]": 2,
        "[SEP]": 3,
        "[MASK]": 4,
    }
    
    def __init__(self, max_length: int = 256):
        self.max_length = max_length
        self._vocab = self.VOCAB.copy()
        self._build_vocab()
    
    def _build_vocab(self) -> None:
        """Build vocabulary from common words."""
        common_words = [
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "have", "has", "had", "do", "does", "did", "will", "would",
            "could", "should", "may", "might", "must", "can", "to", "of",
            "in", "for", "on", "with", "at", "by", "from", "as", "into",
            "through", "during", "before", "after", "above", "below", "between",
            "this", "that", "these", "those", "it", "its", "they", "them",
            "your", "you", "we", "us", "our", "i", "me", "my", "he", "she",
            "him", "her", "his", "account", "bank", "verify", "login", "password",
            "confirm", "urgent", "click", "link", "update", "security", "alert",
        ]
        
        for word in common_words:
            if word not in self._vocab:
                self._vocab[word] = len(self._vocab)
    
    def encode(self, text: str) -> Tuple[np.ndarray, np.ndarray]:
        """Encode text to token IDs.
        
        Returns:
            Tuple of (input_ids, attention_mask) arrays
        """
        tokens = text.lower().split()[: self.max_length - 2]
        
        input_ids = [self._vocab["[CLS]"]]
        for token in tokens:
            input_ids.append(self._vocab.get(token, self._vocab["[UNK]"]))
        input_ids.append(self._vocab["[SEP]"])
        
        while len(input_ids) < self.max_length:
            input_ids.append(self._vocab["[PAD]"])
        
        attention_mask = [1 if id != self._vocab["[PAD]"] else 0 for id in input_ids]
        
        return (
            np.array([input_ids], dtype=np.int32),
            np.array([attention_mask], dtype=np.int32),
        )
    
    def decode(self, input_ids: List[int]) -> str:
        """Decode token IDs back to text."""
        tokens = []
        reverse_vocab = {v: k for k, v in self._vocab.items()}
        
        for id in input_ids:
            if id == self._vocab["[PAD]"]:
                break
            token = reverse_vocab.get(id, "[UNK]")
            if token not in ["[CLS]", "[SEP]", "[PAD]"]:
                tokens.append(token)
        
        return " ".join(tokens)


def load_model(
    model_path: str,
    model_type: str = "onnx",
) -> PhishingDetectorModel:
    """Load a phishing detection model.
    
    Args:
        model_path: Path to the model file
        model_type: Type of model ("onnx" or "tflite")
    
    Returns:
        Loaded PhishingDetectorModel instance
    """
    return PhishingDetectorModel(model_path, model_type)


def convert_to_tflite(
    onnx_path: str,
    output_path: str,
) -> None:
    """Convert ONNX model to TFLite format.
    
    Args:
        onnx_path: Path to input ONNX model
        output_path: Path to output TFLite model
    """
    try:
        import tensorflow as tf
    except ImportError:
        raise RuntimeError("TensorFlow is required for TFLite conversion")
    
    converter = tf.lite.TFLiteConverter.from_onnx_model(onnx_path)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    
    tflite_model = converter.convert()
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(tflite_model)
    
    logger.info(f"Converted ONNX model to TFLite: {output_path}")


def convert_to_onnx(
    pytorch_model,
    output_path: str,
    input_shape: Tuple[int, ...] = (1, 256),
) -> None:
    """Export PyTorch model to ONNX format.
    
    Args:
        pytorch_model: PyTorch model to convert
        output_path: Path to output ONNX model
        input_shape: Shape of input tensor
    """
    import torch
    
    dummy_input = torch.randn(*input_shape)
    
    torch.onnx.export(
        pytorch_model,
        dummy_input,
        output_path,
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "logits": {0: "batch_size"},
        },
    )
    
    logger.info(f"Exported model to ONNX: {output_path}")