"""Training script for phishing detection model."""
import argparse
import logging
import os
from pathlib import Path
from typing import List, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingDataset(Dataset):
    """Dataset for phishing detection training."""
    
    def __init__(self, texts: List[str], labels: List[int], max_length: int = 256):
        self.texts = texts
        self.labels = labels
        self.max_length = max_length
    
    def __len__(self) -> int:
        return len(self.texts)
    
    def __getitem__(self, idx: int):
        text = self.texts[idx][:self.max_length]
        label = self.labels[idx]
        
        encoding = self._simple_tokenize(text)
        
        return {
            "input_ids": encoding,
            "attention_mask": [1] * len(encoding) + [0] * (self.max_length - len(encoding)),
            "labels": label,
        }
    
    def _simple_tokenize(self, text: str) -> List[int]:
        """Simple tokenization using character mapping."""
        chars = "abcdefghijklmnopqrstuvwxyz0123456789 "
        char_to_id = {c: i + 5 for i, c in enumerate(chars)}
        char_to_id.update({"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3})
        
        tokens = [char_to_id.get(c.lower(), 1) for c in text]
        tokens = tokens[: self.max_length - 2]
        
        return [2] + tokens + [3]


class PhishingClassifier(nn.Module):
    """Simple phishing classifier model."""
    
    def __init__(
        self,
        vocab_size: int = 100,
        embed_dim: int = 128,
        hidden_dim: int = 256,
        num_labels: int = 2,
        max_length: int = 256,
    ):
        super().__init__()
        
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            embed_dim,
            hidden_dim,
            batch_first=True,
            bidirectional=True,
        )
        self.dropout = nn.Dropout(0.3)
        self.fc = nn.Linear(hidden_dim * 2, num_labels)
    
    def forward(self, input_ids, attention_mask=None):
        embedded = self.embedding(input_ids)
        
        lstm_out, (hidden, _) = self.lstm(embedded)
        
        hidden_concat = torch.cat([hidden[0], hidden[1]], dim=1)
        
        output = self.dropout(hidden_concat)
        logits = self.fc(output)
        
        return logits


def generate_synthetic_data(num_samples: int = 1000) -> Tuple[List[str], List[int]]:
    """Generate synthetic phishing data for training."""
    
    phishing_templates = [
        "Urgent: Verify your account within 24 hours or lose access. Click here: {}",
        "Your Amazon order #{} cannot be delivered. Update payment method: {}",
        "Security Alert: Unauthorized login detected from IP {}. Confirm identity: {}",
        "Bank of America: Your account has been suspended. Verify now: {}",
        "Microsoft: Your password expires in 24 hours. Update: {}",
        "PayPal: Unauthorized transaction of ${}. Confirm now: {}",
        "IRS: You have an outstanding refund of ${}. Claim now: {}",
        "Apple: Your iCloud storage is full. Verify: {}",
        "Social Security: Benefits will be suspended. Update info: {}",
        "Amazon Prime: Confirm payment method to avoid suspension: {}",
    ]
    
    safe_messages = [
        "Meeting at 3pm tomorrow in conference room B.",
        "Please review the attached quarterly report when convenient.",
        "Thanks for your help with the project. Let me know if you have questions.",
        "The documents are ready for review in the shared folder.",
        "Can we reschedule our call to next week?",
        "Happy birthday! Hope you have a great day.",
        "The new policy will take effect on January 1st.",
        "Please confirm your availability for next Tuesday.",
        "I've attached the presentation slides for your review.",
        "Thank you for your patience. Let me know if you need anything else.",
    ]
    
    urls = [
        "https://amazn-verify.com/{}",
        "https://secure-paypal-update.net/{}",
        "https://microsoft-account-verify.org/{}",
        "https://bankofamerica-login.io/{}",
        "https://apple-id-verify.top/{}",
    ]
    
    texts = []
    labels = []
    
    for i in range(num_samples // 2):
        template = np.random.choice(phishing_templates)
        url = np.random.choice(urls).format(i + 1000)
        text = template.format(i + 5000, url)
        texts.append(text)
        labels.append(1)
    
    for i in range(num_samples // 2):
        text = np.random.choice(safe_messages)
        texts.append(text)
        labels.append(0)
    
    return texts, labels


def train_epoch(
    model: nn.Module,
    dataloader: DataLoader,
    optimizer,
    criterion,
    device: str,
) -> float:
    """Train for one epoch."""
    model.train()
    total_loss = 0.0
    
    for batch in dataloader:
        input_ids = batch["input_ids"].to(device)
        labels = batch["labels"].to(device)
        
        optimizer.zero_grad()
        
        logits = model(input_ids)
        loss = criterion(logits, labels)
        
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
    
    return total_loss / len(dataloader)


def evaluate(
    model: nn.Module,
    dataloader: DataLoader,
    criterion,
    device: str,
) -> Tuple[float, float]:
    """Evaluate model."""
    model.eval()
    total_loss = 0.0
    correct = 0
    total = 0
    
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)
            
            logits = model(input_ids)
            loss = criterion(logits, labels)
            
            total_loss += loss.item()
            predictions = torch.argmax(logits, dim=1)
            correct += (predictions == labels).sum().item()
            total += labels.size(0)
    
    accuracy = correct / total
    avg_loss = total_loss / len(dataloader)
    
    return avg_loss, accuracy


def main():
    parser = argparse.ArgumentParser(description="Train phishing detection model")
    parser.add_argument("--output-dir", default="./models", help="Output directory")
    parser.add_argument("--epochs", type=int, default=10, help="Number of epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--num-samples", type=int, default=1000, help="Number of training samples")
    parser.add_argument("--max-length", type=int, default=256, help="Max sequence length")
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    logger.info("Generating synthetic training data...")
    texts, labels = generate_synthetic_data(args.num_samples)
    
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    train_dataset = PhishingDataset(train_texts, train_labels, args.max_length)
    val_dataset = PhishingDataset(val_texts, val_labels, args.max_length)
    
    train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")
    
    model = PhishingClassifier(
        vocab_size=100,
        embed_dim=128,
        hidden_dim=256,
        num_labels=2,
        max_length=args.max_length,
    ).to(device)
    
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    criterion = nn.CrossEntropyLoss()
    
    logger.info("Starting training...")
    for epoch in range(args.epochs):
        train_loss = train_epoch(model, train_loader, optimizer, criterion, device)
        val_loss, val_accuracy = evaluate(model, val_loader, criterion, device)
        
        logger.info(
            f"Epoch {epoch + 1}/{args.epochs} - "
            f"Train Loss: {train_loss:.4f} - "
            f"Val Loss: {val_loss:.4f} - "
            f"Val Accuracy: {val_accuracy:.4f}"
        )
    
    # Save model
    model_path = os.path.join(args.output_dir, "phishing_detector.pt")
    torch.save(model.state_dict(), model_path)
    logger.info(f"Model saved to {model_path}")
    
    # Export to ONNX
    try:
        from .detection_pipeline import convert_to_onnx
        
        dummy_input = torch.randint(0, 100, (1, args.max_length))
        torch.onnx.export(
            model,
            dummy_input,
            os.path.join(args.output_dir, "phishing_detector.onnx"),
            input_names=["input_ids"],
            output_names=["logits"],
            dynamic_axes={"input_ids": {0: "batch_size"}},
        )
        logger.info(f"ONNX model exported")
    except Exception as e:
        logger.warning(f"Could not export to ONNX: {e}")
    
    # Export to TFLite if available
    try:
        from .detection_pipeline import convert_to_tflite
        
        onnx_path = os.path.join(args.output_dir, "phishing_detector.onnx")
        tflite_path = os.path.join(args.output_dir, "phishing_detector.tflite")
        
        if os.path.exists(onnx_path):
            convert_to_tflite(onnx_path, tflite_path)
            logger.info(f"TFLite model exported")
    except Exception as e:
        logger.warning(f"Could not export to TFLite: {e}")
    
    logger.info("Training complete!")


if __name__ == "__main__":
    main()