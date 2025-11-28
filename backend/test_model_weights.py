"""
Test if fusion model has trained weights or is random
"""
import tensorflow as tf
import numpy as np

model_path = "D:/Major-Project(SQLi)_Latest/Major-Project(SQLi)_Latest/Major-Project(SQLi)/notebooks/phase7a_results/fusion_model_savedmodel"

print("Loading model...")
model = tf.saved_model.load(model_path)
infer = model.signatures['serving_default']

print("Creating dummy inputs...")
dummy_input = {
    'word_input': tf.constant(np.random.randint(0, 100, (1, 150)), dtype=tf.float32),
    'type_input': tf.constant(np.random.randint(0, 8, (1, 150)), dtype=tf.float32),
    'char_input': tf.constant(np.random.randint(0, 256, (1, 1024)), dtype=tf.float32),
    'structural_input': tf.constant(np.random.rand(1, 66), dtype=tf.float32)
}

print("Running 3 predictions with same input...\n")
pred1 = infer(**dummy_input)
pred2 = infer(**dummy_input)
pred3 = infer(**dummy_input)

output_key = list(pred1.keys())[0]
val1 = float(pred1[output_key][0][0])
val2 = float(pred2[output_key][0][0])
val3 = float(pred3[output_key][0][0])

print(f"Prediction 1: {val1:.6f}")
print(f"Prediction 2: {val2:.6f}")
print(f"Prediction 3: {val3:.6f}")
print(f"\nAll predictions identical? {val1 == val2 == val3}")

if val1 == val2 == val3:
    if 0.45 < val1 < 0.55:
        print("\n MODEL APPEARS UNTRAINED (outputs ~0.5, random weights)")
    else:
        print("\n Model is deterministic (likely trained)")
else:
    print("\n Model has randomness (dropout enabled in inference?)")

# Test with real attack query features
print("\n" + "="*60)
print("Testing with attack-like pattern...")
attack_input = {
    'word_input': tf.constant([[18, 22, 29, 346, 50, 313, 16, 25, 41, 25, 16, 25, 10, 10] + [0]*136], dtype=tf.float32),
    'type_input': tf.constant([[3, 4, 3, 2, 3, 2, 4, 5, 3, 5, 4, 5, 4, 4] + [0]*136], dtype=tf.float32),
    'char_input': tf.constant([[83, 69, 76, 69, 67, 84] + [0]*1018], dtype=tf.float32),
    'structural_input': tf.constant([[1.0, 1.0, 1.0, 0.0] + [0.0]*62], dtype=tf.float32)
}

attack_pred = infer(**attack_input)
attack_val = float(attack_pred[output_key][0][0])
print(f"Attack-like query score: {attack_val:.6f}")

if attack_val < 0.1:
    print(" Model gives very low score for attack pattern")
elif attack_val > 0.7:
    print(" Model recognizes attack pattern")
else:
    print(" Model uncertain about attack pattern")
