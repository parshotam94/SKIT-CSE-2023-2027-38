"""
Training Pipeline for Transformer WAF
Trains model on benign HTTP request logs
"""

import os
import sys
import argparse
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import get_linear_schedule_with_warmup
from typing import List, Dict, Optional
from pathlib import Path
from tqdm import tqdm
import json

