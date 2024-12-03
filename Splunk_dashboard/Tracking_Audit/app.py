from flask import Flask, render_template, request, jsonify
import csv
import os

app = Flask(__name__)

# Route to update CSV file dynamically
@app.route("/update_csv/<filename>", methods=["POST"])
def update_csv(filename):
    file_path = os.path.join('static', filename)  # Đường dẫn tới file CSV
    if not os.path.exists(file_path):
        return jsonify({"message": f"File {filename} not found!"}), 404

    data = request.json  # Dữ liệu JSON từ frontend
    try:
        # Đọc dữ liệu hiện tại trong file CSV
        existing_rows = {}
        with open(file_path, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                existing_rows[row["ID"]] = {
                    "Name": row["Name"],  # Giữ nguyên Name
                }

        # Ghi đè dữ liệu mới, cập nhật Stage và giữ nguyên Name
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=["ID", "Name", "Stage"])
            writer.writeheader()
            for row in data:
                row["Name"] = existing_rows.get(row["ID"], {}).get("Name", row["Name"])  # Giữ nguyên Name nếu có
                writer.writerow(row)

        return jsonify({"message": f"Data successfully saved to {filename}!"})
    except Exception as e:
        return jsonify({"message": f"Error saving file {filename}: {str(e)}"}), 500

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
