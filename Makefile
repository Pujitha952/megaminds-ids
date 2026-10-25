.PHONY: all data train eval test dashboard clean
all: data train eval test
data:
	python generate_traffic.py
train:
	python ids.py train
eval:
	python evaluate.py
test:
	python -m pytest -q
dashboard:
	streamlit run dashboard.py
clean:
	rm -rf results/figures/*.png results/metrics.* __pycache__ idslib/__pycache__
