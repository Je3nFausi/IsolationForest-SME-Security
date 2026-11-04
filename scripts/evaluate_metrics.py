"""
evaluate_metrics.py — Calculates Precision and Recall based on simulation ground truth.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from database.db import get_connection

def calculate_metrics():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # We join alerts and predictions to get the ground truth
            sql = """
                SELECT 
                    p.is_anomaly, 
                    p.ground_truth
                FROM alerts a
                JOIN predictions p ON a.prediction_id = p.id
            """
            cur.execute(sql)
            rows = cur.fetchall()
            
            if not rows:
                print("No alerts found in the database. Run the consumer/producer first.")
                return

            true_positives = 0
            false_positives = 0
            false_negatives = 0
            
            for row in rows:
                is_flagged = row['is_anomaly']
                truth = row['ground_truth']
                
                if is_flagged and truth == 'anomaly':
                    true_positives += 1
                elif is_flagged and truth == 'normal':
                    false_positives += 1
                elif not is_flagged and truth == 'anomaly':
                    false_negatives += 1

            # Precision = TP / (TP + FP)
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            
            # Recall = TP / (TP + FN)
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0

            print("\n=== MODEL PERFORMANCE METRICS ===")
            print(f"Total Alerts Evaluated: {len(rows)}")
            print(f"True Positives (Correct Alerts): {true_positives}")
            print(f"False Positives (False Alarms): {false_positives}")
            print(f"False Negatives (Missed Attacks): {false_negatives}")
            print("-" * 35)
            print(f"PRECISION (Alert Accuracy): {precision:.2%}")
            print(f"RECALL (Threat Coverage):   {recall:.2%}")
            print("=================================\n")

    except Exception as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    calculate_metrics()