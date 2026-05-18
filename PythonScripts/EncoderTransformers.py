import torch
import torch.nn as nn
import math


class PositionalEncoding(nn.Module):
    def __init__(self, embeddingDimension, contextWindow, dropout=0.1):
        CONTEXT_WINDOW = contextWindow
        super(PositionalEncoding, self).__init__()
        self.dropout = nn.Dropout(p=dropout)

        # Create a matrix of shape (max_len, d_model) for positional encodings
        positionalEncodingTensor = torch.zeros(CONTEXT_WINDOW, embeddingDimension)

        # Create position indices [0, 1, 2, ..., max_len-1]
        position = torch.arange(0, CONTEXT_WINDOW, dtype=torch.float).unsqueeze(1)

        # Create scaling factors for different dimensions
        div_term = torch.exp(torch.arange(0, embeddingDimension, 2).float() * (-math.log(10000.0) / embeddingDimension))

        # Apply sine to even indices
        positionalEncodingTensor[:, 0::2] = torch.sin(position * div_term)

        # Apply cosine to odd indices
        positionalEncodingTensor[:, 1::2] = torch.cos(position * div_term)

        # Add batch dimension: (1, max_len, d_model)
        positionalEncodingTensor = positionalEncodingTensor.unsqueeze(0)

        # Register as buffer (not a trainable parameter, but part of the model state)
        self.register_buffer('pe', positionalEncodingTensor)

    def forward(self, x):
        # Add positional encoding to input
        x = x + self.pe[:, :x.size(1), :]
        return self.dropout(x)  # Tensor with positional encoding added


class TransformerEncoderLayer(nn.Module):

    def __init__(self, embeddingDimension, attentionHeads, feedforwardDim, dropout=0.1):
        super(TransformerEncoderLayer, self).__init__()

        # Multi-head self-attention
        self.self_attn = nn.MultiheadAttention(
            embeddingDimension,
            attentionHeads,  # Number of attention heads
            dropout=dropout,
            batch_first=True  # Input shape: (batch, seq_len, d_model)
        )

        # Feed-forward network (2 linear layers with activation)
        self.linear1 = nn.Linear(embeddingDimension, feedforwardDim)
        self.dropout = nn.Dropout(dropout)
        self.linear2 = nn.Linear(feedforwardDim, embeddingDimension)

        # Layer normalization (normalizes across features)
        self.norm1 = nn.LayerNorm(embeddingDimension)
        self.norm2 = nn.LayerNorm(embeddingDimension)

        # Dropout layers
        self.dropout1 = nn.Dropout(dropout)
        self.dropout2 = nn.Dropout(dropout)

    def forward(self, src, src_key_padding_mask=None):
        # Multi-head self-attention with residual connection
        # Query, Key, Value are all the same (self-attention)
        src2, _ = self.self_attn(
            src, src, src,  # query, key, value
            key_padding_mask=src_key_padding_mask
        )
        src = src + self.dropout1(src2)  # Residual connection
        src = self.norm1(src)  # Layer normalization

        # Feed-forward network with residual connection
        src2 = self.linear2(self.dropout(torch.relu(self.linear1(src))))
        src = src + self.dropout2(src2)  # Residual connection
        src = self.norm2(src)  # Layer normalization

        return src


class EncoderTransformerClassifier(nn.Module):
    def __init__(
            self,
            vocab_size,  # Size of tokenizer vocabulary
            d_model=256,  # Embedding dimension (MUST be divisible by nhead)
            nhead=8,  # Number of attention heads
            num_layers=4,  # Number of encoder layers
            dim_feedforward=2048,  # Feed-forward hidden dimension
            num_classes=2,  # Defining how many classification classes the model will predict
            dropout=0.1,  # Dropout rate
            contextWindow=30 # Content context window
    ):
        super(EncoderTransformerClassifier, self).__init__()

        self.d_model = d_model

        # Token embedding: converts token IDs to dense vectors
        self.embedding = nn.Embedding(vocab_size, d_model)

        # Positional encoding: adds position information
        self.pos_encoder = PositionalEncoding(d_model, contextWindow, dropout)

        # Stack of transformer encoder layers
        self.encoder_layers = nn.ModuleList([
            TransformerEncoderLayer(d_model, nhead, dim_feedforward, dropout)
            for _ in range(num_layers)
        ])

        # Classification head: converts encoder output to class predictions
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),  # Reduce dimension
            nn.ReLU(),  # Non-linearity
            nn.Dropout(dropout),  # Regularization
            nn.Linear(d_model // 2, num_classes)  # Final prediction
        )

        # Initialize weights
        self._init_weights()

    def _init_weights(self):
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.xavier_uniform_(p)

    def forward(self, input_ids, attention_mask=None):
        # Step 1: Convert token IDs to embeddings
        x = self.embedding(input_ids) * math.sqrt(self.d_model)
        # Multiply by sqrt(d_model) for scaling (helps with training stability)

        # Step 2: Add positional encoding
        x = self.pos_encoder(x)

        # Step 3: Create padding mask for attention
        # Convert attention_mask: 0 (padding) -> True (ignore), 1 (real) -> False (attend)
        if attention_mask is not None:
            src_key_padding_mask = (attention_mask == 0)
        else:
            src_key_padding_mask = None

        # Step 4: Pass through encoder layers
        for layer in self.encoder_layers:
            x = layer(x, src_key_padding_mask=src_key_padding_mask)

        # Step 5: Global average pooling
        # Average over sequence dimension, excluding padding tokens
        if attention_mask is not None:
            # Expand mask to match embedding dimensions
            mask_expanded = attention_mask.unsqueeze(-1).expand(x.size())
            # Sum embeddings (masked)
            sum_embeddings = torch.sum(x * mask_expanded, dim=1)
            # Count non-padding tokens
            sum_mask = torch.clamp(mask_expanded.sum(dim=1), min=1e-9)
            # Average
            x = sum_embeddings / sum_mask
        else:
            x = x.mean(dim=1)

        # Step 6: Classification
        logits = self.classifier(x)

        return logits

    def get_num_params(self):
        """Return the number of trainable parameters"""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)




def loadClassifierModel(modelPath, modelType, classificationTask, device='mps'):
    # Create model architecture (must match saved model!)
    if modelType == "Allen AI":
        vocabSize = 50265
    else:
        vocabSize = 28996

    if classificationTask == "Password Strength":
        model = EncoderTransformerClassifier(
            vocab_size=vocabSize,
            d_model=64,
            nhead=2,
            num_layers=2,
            dim_feedforward=128,
            num_classes=5,
            dropout=0.1,
            contextWindow=30
        )
    else:
        if classificationTask == "Phishing Emails":
            numClasses = 2
        else:
            numClasses = 5
        model = EncoderTransformerClassifier(
            vocab_size=vocabSize,
            d_model=256,
            nhead=8,
            num_layers=3,
            dim_feedforward=768,
            num_classes=numClasses,
            dropout=0.1,
            contextWindow=1500
        )

    # Load weights
    model.load_state_dict(torch.load(modelPath, weights_only=True))
    model = model.to(device)
    model.eval()  # Set to evaluation mode

    print(f"✓ Model loaded from: {modelPath}")
    print(f"✓ Model on device: {device}")
    print(f"✓ Model in evaluation mode")
    return model


def Prediction(content, tokenizer, model, classificationTask, device='mps'):
    if classificationTask == "Password Strength":
        tokenizer.model_max_length = 30
    else:
        tokenizer.model_max_length = 1500
    encoding = tokenizer(content, add_special_tokens=True, padding='max_length', return_tensors='pt', truncation=True)
    input_ids = encoding['input_ids'].to(device)
    attention_mask = encoding['attention_mask'].to(device)
    # Predict
    with torch.no_grad():
        logits = model(input_ids, attention_mask)
        probs = torch.softmax(logits, dim=1)
        prediction = torch.argmax(probs, dim=1).item()
        confidence = probs[0, prediction].item()
    return prediction, confidence



