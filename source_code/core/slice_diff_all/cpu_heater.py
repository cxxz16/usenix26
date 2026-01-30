import multiprocessing
from tqdm import tqdm

def multiprocess(worker_args, func, max_workers=4, show_progress=True):
    """
    并行执行函数 func，传入参数列表 worker_args
    :param worker_args: 可迭代的参数（如 [(arg1,), (arg2,), ...] 或 [arg1, arg2, ...]）
    :param func: 被并行执行的函数
    :param max_workers: 最大并行数
    :param show_progress: 是否显示进度条
    :return: 返回所有执行结果的列表
    """
    with multiprocessing.Pool(processes=max_workers) as pool:
        if show_progress:
            results = list(tqdm(pool.imap(func, worker_args), total=len(worker_args)))
        else:
            results = pool.map(func, worker_args)
    return results
