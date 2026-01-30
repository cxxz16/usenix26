import openai
import tiktoken
import configparser
from datetime import datetime
# from anthropic._tokenizer import tokenizer as claude_tokenizer
config = configparser.ConfigParser()
config.read("./core/config.ini")

api_key = config["database"]["api_key"] 
base_url = config["database"]["api_base"]
default_model = config["database"]["model_name"]


def set_logger():
    current_time = datetime.now().strftime("%Y-%m-%d_%H_%M")
    lf = f"./logs/chatlog_{current_time}.log"
    os.makedirs("./logs", exist_ok=True)
    logger = setup_logging(lf, True)
    return logger

def openai_chat(prompt, model=default_model, temperature=0.1, system_prompt=None, assistant_prompt=None, custom_api_key=None):
    logger = set_logger()
    logger.info("Model: %s", model)
    logger.info("temperature: %s", temperature)
    # logger.info("User:\n%s", prompt)
    client = openai.OpenAI(api_key=custom_api_key if custom_api_key else api_key, base_url=base_url)
    assis_prompt = """###1 You are an expert in software security with a specialization in secure code auditing. \n###2 Please analyze the information provided by the user and answer the user's question.""" if assistant_prompt is None else assistant_prompt
    system_prompt = "You are an expert in software security with a specialization in secure code auditing." if system_prompt is None else system_prompt
    response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "assistant",
                "content": assis_prompt,
            },
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model=model,
        temperature=temperature,
    )
    response = response.choices[0].message.content
    # logger.info("Chatbot:\n%s", str(response))
    return response


import os
import logging

def setup_logging(log_file=None, clear_logfile=False):
    if log_file and clear_logfile:
        if os.path.exists(log_file):
            with open(log_file, 'w'):
                pass

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(levelname)-8s - %(filename)s:%(lineno)d - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO) 
    console_handler.setFormatter(formatter)
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)

    class LessThanInfoFilter(logging.Filter):
        def filter(self, record):
            return record.levelno < logging.INFO

    console_handler.addFilter(LessThanInfoFilter())

    logger.addHandler(console_handler)
    if log_file:
        logger.addHandler(file_handler)

    return logger